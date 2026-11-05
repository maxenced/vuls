//go:build !scanner

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/models"
)

// sparseCveContent is the part of a models.CveContent a sparse response keeps:
// which source it comes from and how it scores the CVE. Summary, references,
// CPEs, CWEs and the rest are what make a full response heavy, and are left
// out. Field names and JSON tags match models.CveContent, so a client decoding
// a sparse response into models.ScanResult reads these fields unchanged and
// finds the others empty.
type sparseCveContent struct {
	Type           models.CveContentType `json:"type"`
	CveID          string                `json:"cveID"`
	Cvss2Score     float64               `json:"cvss2Score"`
	Cvss2Vector    string                `json:"cvss2Vector"`
	Cvss2Severity  string                `json:"cvss2Severity"`
	Cvss3Score     float64               `json:"cvss3Score"`
	Cvss3Vector    string                `json:"cvss3Vector"`
	Cvss3Severity  string                `json:"cvss3Severity"`
	Cvss40Score    float64               `json:"cvss40Score"`
	Cvss40Vector   string                `json:"cvss40Vector"`
	Cvss40Severity string                `json:"cvss40Severity"`
}

// sparseVulnInfo is a models.VulnInfo whose cveContents are sparse. The outer
// CveContents is less nested than the embedded one, so encoding/json marshals
// it in place of VulnInfo.CveContents under the same key.
type sparseVulnInfo struct {
	models.VulnInfo
	CveContents map[models.CveContentType][]sparseCveContent `json:"cveContents,omitempty"`
}

// sparseScanResult is a models.ScanResult whose scannedCves carry sparse
// cveContents, the same shadowing as sparseVulnInfo.
type sparseScanResult struct {
	models.ScanResult
	ScannedCves map[string]sparseVulnInfo `json:"scannedCves"`
}

func toSparse(r models.ScanResult) sparseScanResult {
	vinfos := make(map[string]sparseVulnInfo, len(r.ScannedCves))
	for id, v := range r.ScannedCves {
		var conts map[models.CveContentType][]sparseCveContent
		if len(v.CveContents) > 0 {
			conts = make(map[models.CveContentType][]sparseCveContent, len(v.CveContents))
			for typ, cs := range v.CveContents {
				scs := make([]sparseCveContent, 0, len(cs))
				for _, c := range cs {
					scs = append(scs, sparseCveContent{
						Type:           c.Type,
						CveID:          c.CveID,
						Cvss2Score:     c.Cvss2Score,
						Cvss2Vector:    c.Cvss2Vector,
						Cvss2Severity:  c.Cvss2Severity,
						Cvss3Score:     c.Cvss3Score,
						Cvss3Vector:    c.Cvss3Vector,
						Cvss3Severity:  c.Cvss3Severity,
						Cvss40Score:    c.Cvss40Score,
						Cvss40Vector:   c.Cvss40Vector,
						Cvss40Severity: c.Cvss40Severity,
					})
				}
				conts[typ] = scs
			}
		}
		vinfos[id] = sparseVulnInfo{VulnInfo: v, CveContents: conts}
	}
	return sparseScanResult{ScanResult: r, ScannedCves: vinfos}
}

// sparseRequested tells whether this request gets a sparse response: the
// request's sparse query parameter when it has one, the server's default
// otherwise.
func sparseRequested(def bool, q url.Values) (bool, error) {
	if !q.Has("sparse") {
		return def, nil
	}
	b, err := strconv.ParseBool(q.Get("sparse"))
	if err != nil {
		return false, xerrors.Errorf("Invalid sparse query parameter %q: want true or false", q.Get("sparse"))
	}
	return b, nil
}

// sparseResponseWriter writes results to the HTTP response as
// reporter.HTTPResponseWriter does, a JSON array of scan results, with sparse
// cveContents.
type sparseResponseWriter struct {
	Writer http.ResponseWriter
}

// Write sends results as HTTP response
func (w sparseResponseWriter) Write(rs ...models.ScanResult) error {
	srs := make([]sparseScanResult, 0, len(rs))
	for _, r := range rs {
		srs = append(srs, toSparse(r))
	}
	res, err := json.Marshal(srs)
	if err != nil {
		return xerrors.Errorf("Failed to marshal scan results: %w", err)
	}
	w.Writer.Header().Set("Content-Type", "application/json")
	if _, err := w.Writer.Write(res); err != nil {
		return xerrors.Errorf("Failed to write response. err: %w", err)
	}
	return nil
}
