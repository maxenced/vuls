package vuls2

import "github.com/MaineK00n/vuls2/pkg/db/session"

// Install exposes SharedDB.install so tests can retire a generation without a
// real fetch, which is the only way a new db reaches install in production.
func (d *SharedDB) Install(sesh *session.Session) { d.install(sesh) }

// Inner exposes the db a Session queries, so tests can tell which generation
// they were handed and whether it is still open.
func (s *Session) Inner() *session.Session { return s.sesh }

var (
	ShouldDownload = shouldDownload
	MustFetchSync  = mustFetchSync

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
	bgFetch.mu.Unlock()
}
