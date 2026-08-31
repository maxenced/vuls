package vuls2

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"

	"github.com/MaineK00n/vuls2/pkg/db/fetch"
	"github.com/MaineK00n/vuls2/pkg/db/session"
)

var (
	// DefaultPath is the path for vuls2 db file
	DefaultPath = func() string {
		wd, _ := os.Getwd()
		return filepath.Join(wd, "vuls.db")
	}()

	bgFetch backgroundFetch
)

// newDBConfig downloads or refreshes the db if due, validates its schema
// version, and returns the session config to open it with.
//
// withCache decides whether the returned session carries a read cache. Any
// session that answers a detection wants one: without it, enrichment re-reads
// and re-unmarshals the same advisory and vulnerability records once per root
// that references them, ~60x slower on a 4873-CVE result. The cache is
// unbounded (a sync.Map that never evicts), so it is only safe on a session
// whose lifetime is bounded — one server's detection run, or one request. A
// session meant to outlive those must pass false, which is why SharedDB opens
// the db without one when it is only checking that the db is usable.
func newDBConfig(vuls2Conf config.Vuls2Conf, noProgress, withCache bool) (*session.Config, error) {
	willDownload, err := shouldDownload(vuls2Conf, time.Now())
	if err != nil {
		return nil, xerrors.Errorf("Failed to check whether to download vuls2 db. err: %w", err)
	}

	if willDownload {
		syncRequired, err := mustFetchSync(vuls2Conf.Path)
		if err != nil {
			return nil, xerrors.Errorf("Failed to check db state. err: %w", err)
		}

		if syncRequired {
			// DB does not exist or has incompatible schema — must download synchronously.
			logging.Log.Infof("Fetching vuls2 db (sync). repository: %s", vuls2Conf.Repository)
			if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
				return nil, xerrors.Errorf("Failed to fetch vuls2 db. err: %w", err)
			}
		} else {
			// DB exists with correct schema but is stale — trigger a background
			// refresh and continue with the current version.
			bgFetch.triggerAsync(vuls2Conf, noProgress)
		}
	}

	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    vuls2Conf.Path,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		return nil, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := sesh.Storage().Open(); err != nil {
		return nil, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return nil, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil {
		return nil, xerrors.Errorf("unexpected vuls2 db metadata. metadata: nil, path: %s", vuls2Conf.Path)
	}
	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		return nil, xerrors.Errorf("Failed to get schema version. err: %w", err)
	}
	if metadata.SchemaVersion != sv {
		return nil, xerrors.Errorf("vuls2 db schema version mismatch. expected: %d, actual: %d", session.SchemaVersion, metadata.SchemaVersion)
	}

	return &session.Config{
		Type:      "boltdb",
		Path:      vuls2Conf.Path,
		Options:   session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
		WithCache: withCache,
	}, nil
}

// hasNewerRemote reports whether the repository holds a db other than the one on
// disk, comparing the manifest digest that fetch recorded in the local db's
// metadata against the digest the repository's reference resolves to now.
//
// shouldDownload can only tell that the local db is old enough to be worth
// checking: it goes by timestamps, and the nightly db's LastModified is the
// night it was built, so a db past the staleness window looks due on every
// check until something replaces it. Downloading on that alone re-fetches
// gigabytes on every check even when the tag has not moved. Resolving the
// manifest costs one request, so it is worth asking before spending a download.
func hasNewerRemote(ctx context.Context, vuls2Conf config.Vuls2Conf) (bool, error) {
	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    vuls2Conf.Path,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		return false, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := sesh.Storage().Open(); err != nil {
		return false, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return false, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil || metadata.Digest == nil {
		// A db that was built locally rather than fetched carries no digest, so
		// there is nothing to compare it by and the repository's db counts as
		// the newer one.
		return true, nil
	}

	repo, err := remote.NewRepository(vuls2Conf.Repository)
	if err != nil {
		return false, xerrors.Errorf("Failed to create client for %s. err: %w", vuls2Conf.Repository, err)
	}
	if repo.Reference.Reference == "" {
		return false, xerrors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, vuls2Conf.Repository)
	}

	desc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return false, xerrors.Errorf("Failed to resolve %s. err: %w", vuls2Conf.Repository, err)
	}

	return desc.Digest.String() != *metadata.Digest, nil
}

func shouldDownload(vuls2Conf config.Vuls2Conf, now time.Time) (bool, error) {
	if _, err := os.Stat(vuls2Conf.Path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if vuls2Conf.SkipUpdate {
				return false, xerrors.Errorf("%s not found, cannot skip update", vuls2Conf.Path)
			}
			return true, nil
		}
		return false, xerrors.Errorf("Failed to stat vuls2 db file. err: %w", err)
	}

	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    vuls2Conf.Path,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		return false, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := sesh.Storage().Open(); err != nil {
		return false, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return false, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil {
		return false, xerrors.Errorf("unexpected vuls2 db metadata. metadata: nil, path: %s", vuls2Conf.Path)
	}

	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		return false, xerrors.Errorf("Failed to get schema version. err: %w", err)
	}

	if metadata.SchemaVersion != sv {
		if vuls2Conf.SkipUpdate {
			return false, xerrors.Errorf("vuls2 db schema version mismatch. expected: %d, actual: %d", sv, metadata.SchemaVersion)
		}
		return true, nil
	}

	if vuls2Conf.SkipUpdate {
		return false, nil
	}

	if metadata.Downloaded != nil && now.Before((*metadata.Downloaded).Add(1*time.Hour)) {
		return false, nil
	}
	return metadata.LastModified.Add(6 * time.Hour).Before(now), nil
}

// triggerAsync starts a background fetch if no download is already in progress.
// It returns immediately in all cases — the caller continues with the current DB.
func (bf *backgroundFetch) triggerAsync(vuls2Conf config.Vuls2Conf, noProgress bool) {
	bf.mu.Lock()
	if bf.downloading {
		bf.mu.Unlock()
		logging.Log.Infof("vuls2 db download already in progress, using current db")
		return
	}
	bf.downloading = true
	bf.mu.Unlock()

	logging.Log.Infof("Fetching vuls2 db in background. repository: %s", vuls2Conf.Repository)
	go func() {
		defer func() {
			bf.mu.Lock()
			bf.downloading = false
			bf.mu.Unlock()
		}()

		if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
			logging.Log.Warnf("Background vuls2 db fetch failed: %+v", err)
		} else {
			logging.Log.Infof("Background vuls2 db fetch completed successfully")
		}
	}()
}

// StartInitialFetch triggers a one-time background download of the vuls2 DB at
// server startup. It fills in the default repository/path just like openSession
// does. The /health endpoint reports 503 until the download finishes. If the DB
// already exists with a valid schema, the initial fetch is considered done
// immediately and a normal background refresh is triggered instead.
func StartInitialFetch(vuls2Conf config.Vuls2Conf, noProgress bool) {
	if vuls2Conf.Repository == "" {
		sv, err := session.SchemaVersion("boltdb")
		if err != nil {
			logging.Log.Warnf("StartInitialFetch: failed to get schema version: %+v", err)
			return
		}
		vuls2Conf.Repository = fmt.Sprintf("%s:%d", defaultRegistory, sv)
	}
	if vuls2Conf.Path == "" {
		vuls2Conf.Path = DefaultPath
	}

	syncRequired, err := mustFetchSync(vuls2Conf.Path)
	if err != nil {
		logging.Log.Warnf("StartInitialFetch: failed to check db state: %+v", err)
		return
	}

	if !syncRequired {
		// DB already usable — mark ready immediately, trigger a background
		// refresh for staleness (same as a normal request would).
		bgFetch.mu.Lock()
		bgFetch.initialDone = make(chan struct{})
		close(bgFetch.initialDone)
		bgFetch.mu.Unlock()

		willDownload, _ := shouldDownload(vuls2Conf, time.Now())
		if willDownload {
			bgFetch.triggerAsync(vuls2Conf, noProgress)
		}
		return
	}

	// DB doesn't exist or schema mismatch — download in background and mark
	// not-ready until complete.
	bgFetch.mu.Lock()
	bgFetch.initialDone = make(chan struct{})
	bgFetch.downloading = true
	bgFetch.mu.Unlock()

	logging.Log.Infof("Starting initial vuls2 db download. repository: %s", vuls2Conf.Repository)
	go func() {
		defer func() {
			bgFetch.mu.Lock()
			bgFetch.downloading = false
			close(bgFetch.initialDone)
			bgFetch.mu.Unlock()
		}()

		if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
			logging.Log.Errorf("Initial vuls2 db fetch failed: %+v", err)
			bgFetch.mu.Lock()
			bgFetch.initialErr = err
			bgFetch.mu.Unlock()
		} else {
			logging.Log.Infof("Initial vuls2 db fetch completed successfully")
		}
	}()
}

// Ready reports whether the vuls2 DB is available for serving requests.
// It returns false with a descriptive message while the initial startup
// download is still in progress.
func Ready() (ok bool, msg string) {
	bgFetch.mu.Lock()
	done := bgFetch.initialDone
	bgFetch.mu.Unlock()

	if done == nil {
		// No startup fetch was requested (e.g. skipUpdate or not configured).
		return true, "ok"
	}

	select {
	case <-done:
		bgFetch.mu.Lock()
		err := bgFetch.initialErr
		bgFetch.mu.Unlock()
		if err != nil {
			return false, fmt.Sprintf("initial vuls2 db fetch failed: %v", err)
		}
		return true, "ok"
	default:
		return false, "downloading vuls2"
	}
}

// Downloading reports whether a background fetch is currently in progress.
func Downloading() bool {
	bgFetch.mu.Lock()
	defer bgFetch.mu.Unlock()
	return bgFetch.downloading
}
