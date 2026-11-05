//go:build !scanner

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
)

func fullScanResult() models.ScanResult {
	published := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	return models.ScanResult{
		ServerName: "host1",
		Family:     "ubuntu",
		Release:    "22.04",
		ScannedCves: models.VulnInfos{
			"CVE-2024-0001": {
				CveID:            "CVE-2024-0001",
				Confidences:      models.Confidences{models.OvalMatch},
				AffectedPackages: models.PackageFixStatuses{{Name: "openssl", FixedIn: "3.0.2-0ubuntu1.15"}},
				DistroAdvisories: models.DistroAdvisories{{AdvisoryID: "USN-1234-1", Severity: "high"}},
				CveContents: models.CveContents{
					models.Nvd: {{
						Type:           models.Nvd,
						CveID:          "CVE-2024-0001",
						Title:          "a title",
						Summary:        "a long summary",
						Cvss2Score:     5.0,
						Cvss2Vector:    "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Cvss2Severity:  "MEDIUM",
						Cvss3Score:     7.5,
						Cvss3Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						Cvss3Severity:  "HIGH",
						Cvss40Score:    8.7,
						Cvss40Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
						Cvss40Severity: "HIGH",
						SSVC:           &models.SSVC{Exploitation: "none"},
						SourceLink:     "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
						Cpes:           []models.Cpe{{URI: "cpe:/a:openssl:openssl:3.0.2"}},
						References:     models.References{{Link: "https://example.com/advisory", Source: "MISC"}},
						CweIDs:         []string{"CWE-400"},
						Published:      published,
						LastModified:   published,
						Optional:       map[string]string{"key": "value"},
					}},
					models.UbuntuAPI: {{
						Type:          models.UbuntuAPI,
						CveID:         "CVE-2024-0001",
						Summary:       "ubuntu summary",
						Cvss3Severity: "medium",
					}},
				},
			},
			"CVE-2024-0002": {
				CveID:            "CVE-2024-0002",
				AffectedPackages: models.PackageFixStatuses{{Name: "curl", NotFixedYet: true}},
			},
		},
	}
}

func TestToSparse(t *testing.T) {
	in := fullScanResult()
	got := toSparse(in)

	if got.ServerName != in.ServerName || got.Family != in.Family || got.Release != in.Release {
		t.Errorf("scan result fields not kept: got %s/%s/%s", got.ServerName, got.Family, got.Release)
	}
	if len(got.ScannedCves) != len(in.ScannedCves) {
		t.Fatalf("len(ScannedCves) = %d, want %d", len(got.ScannedCves), len(in.ScannedCves))
	}

	v := got.ScannedCves["CVE-2024-0001"]
	want := in.ScannedCves["CVE-2024-0001"]
	if !reflect.DeepEqual(v.AffectedPackages, want.AffectedPackages) ||
		!reflect.DeepEqual(v.DistroAdvisories, want.DistroAdvisories) ||
		!reflect.DeepEqual(v.Confidences, want.Confidences) {
		t.Errorf("vuln info fields not kept: got %+v", v.VulnInfo)
	}

	wantConts := map[models.CveContentType][]sparseCveContent{
		models.Nvd: {{
			Type:           models.Nvd,
			CveID:          "CVE-2024-0001",
			Cvss2Score:     5.0,
			Cvss2Vector:    "AV:N/AC:L/Au:N/C:N/I:N/A:P",
			Cvss2Severity:  "MEDIUM",
			Cvss3Score:     7.5,
			Cvss3Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Cvss3Severity:  "HIGH",
			Cvss40Score:    8.7,
			Cvss40Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
			Cvss40Severity: "HIGH",
		}},
		models.UbuntuAPI: {{
			Type:          models.UbuntuAPI,
			CveID:         "CVE-2024-0001",
			Cvss3Severity: "medium",
		}},
	}
	if !reflect.DeepEqual(v.CveContents, wantConts) {
		t.Errorf("CveContents = %+v, want %+v", v.CveContents, wantConts)
	}

	if conts := got.ScannedCves["CVE-2024-0002"].CveContents; conts != nil {
		t.Errorf("CVE without cveContents got %+v, want nil", conts)
	}
}

func TestSparseResponseWriter(t *testing.T) {
	in := fullScanResult()
	rec := httptest.NewRecorder()
	if err := (sparseResponseWriter{Writer: rec}).Write(in); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	for _, dropped := range []string{"a long summary", "ubuntu summary", "a title", "example.com/advisory", "CWE-400", "cpe:/a:openssl", "sourceLink", "ssvc", "optional", "published"} {
		if strings.Contains(body, dropped) {
			t.Errorf("sparse response still contains %q", dropped)
		}
	}
	// The embedded VulnInfo.CveContents must be shadowed, not marshaled alongside.
	if n := strings.Count(body, `"cveContents"`); n != 1 {
		t.Errorf("found %d cveContents keys, want 1", n)
	}

	// A client decoding into the vuls models reads the kept fields unchanged.
	var rs []models.ScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &rs); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(rs))
	}
	got := rs[0].ScannedCves["CVE-2024-0001"]
	full := in.ScannedCves["CVE-2024-0001"].CveContents[models.Nvd][0]
	wantNvd := models.CveContent{
		Type:           full.Type,
		CveID:          full.CveID,
		Cvss2Score:     full.Cvss2Score,
		Cvss2Vector:    full.Cvss2Vector,
		Cvss2Severity:  full.Cvss2Severity,
		Cvss3Score:     full.Cvss3Score,
		Cvss3Vector:    full.Cvss3Vector,
		Cvss3Severity:  full.Cvss3Severity,
		Cvss40Score:    full.Cvss40Score,
		Cvss40Vector:   full.Cvss40Vector,
		Cvss40Severity: full.Cvss40Severity,
	}
	if !reflect.DeepEqual(got.CveContents[models.Nvd], []models.CveContent{wantNvd}) {
		t.Errorf("decoded nvd content = %+v, want %+v", got.CveContents[models.Nvd], wantNvd)
	}
	if !reflect.DeepEqual(got.AffectedPackages, in.ScannedCves["CVE-2024-0001"].AffectedPackages) {
		t.Errorf("decoded affectedPackages = %+v", got.AffectedPackages)
	}
	if rs[0].ServerName != "host1" {
		t.Errorf("decoded serverName = %q, want host1", rs[0].ServerName)
	}
}

func TestSparseRequested(t *testing.T) {
	tests := []struct {
		query   string
		def     bool
		want    bool
		wantErr bool
	}{
		{query: "", def: false, want: false},
		{query: "", def: true, want: true},
		{query: "sparse=true", def: false, want: true},
		{query: "sparse=1", def: false, want: true},
		{query: "sparse=false", def: true, want: false},
		{query: "sparse=0", def: true, want: false},
		{query: "sparse=", def: false, wantErr: true},
		{query: "sparse=yes", def: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			q, err := url.ParseQuery(tt.query)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sparseRequested(tt.def, q)
			if (err != nil) != tt.wantErr {
				t.Fatalf("sparseRequested() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("sparseRequested() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServeHTTPRejectsInvalidSparse(t *testing.T) {
	// No db: the parameter is refused before the handler needs one.
	h := NewVulsHandler(false, false, nil, 0)
	req := httptest.NewRequest(http.MethodPost, "/vuls?sparse=maybe", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
