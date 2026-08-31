package vuls2

import "github.com/MaineK00n/vuls2/pkg/db/session"

// Open exposes Session.open so tests can force the lazy open and inspect what
// it produced.
func (s *Session) Open() (*session.Session, error) { return s.open() }

// SkipsUpdate reports whether this Session is barred from downloading a db, so
// a test can assert that the request path cannot fetch.
func (s *Session) SkipsUpdate() bool { return s.vuls2Conf.SkipUpdate }

var (
	ShouldDownload = shouldDownload
	HasNewerRemote = hasNewerRemote

	PreConvertPkgs   = preConvertPkgs
	PreConvertCPEs   = preConvertCPEs
	PostConvert      = postConvert
	PrunePkgCriteria = prunePkgCriteria
	Enrich           = enrich
	EnrichCTI        = enrichCTI

	WalkCPECriteria      = walkCPECriteria
	MergeIntoScannedCves = mergeIntoScannedCves

	CollectVerifiedProducts = collectVerifiedProducts

	WarningMessages = warningMessages
)

type Source source

// BgFetchDownloading exposes the downloading state for tests.
func BgFetchDownloading() bool {
	bgFetch.mu.Lock()
	defer bgFetch.mu.Unlock()
	return bgFetch.downloading
}

// ResetBgFetch resets the background fetch state between tests.
func ResetBgFetch() {
	bgFetch.mu.Lock()
	bgFetch.downloading = false
	bgFetch.initialDone = nil
	bgFetch.initialErr = nil
	bgFetch.mu.Unlock()
}

// SetInitialDone simulates a completed startup fetch for testing.
func SetInitialDone(err error) {
	bgFetch.mu.Lock()
	bgFetch.initialDone = make(chan struct{})
	close(bgFetch.initialDone)
	bgFetch.initialErr = err
	bgFetch.mu.Unlock()
}

// SetInitialInProgress simulates a startup fetch still in progress.
func SetInitialInProgress() {
	bgFetch.mu.Lock()
	bgFetch.initialDone = make(chan struct{})
	bgFetch.downloading = true
	bgFetch.mu.Unlock()
}
