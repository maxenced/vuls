//go:build !scanner

package server

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/models"
)

func TestCpesFromRequest(t *testing.T) {
	tests := []struct {
		name string
		in   models.ScanResult
		want []vuls2.CPE
	}{
		{
			name: "no config in payload",
			in:   models.ScanResult{ServerName: "host1"},
			want: nil,
		},
		{
			name: "cpeNames of the scanned server",
			in: func() models.ScanResult {
				r := models.ScanResult{ServerName: "host1"}
				r.Config.Scan.Servers = map[string]config.ServerInfo{
					"host1": {CpeNames: []string{
						"cpe:2.3:a:php:php:7.3.33:*:*:*:*:*:*:*",
						"cpe:/a:openssl:openssl:1.1.1w",
					}},
				}
				return r
			}(),
			want: []vuls2.CPE{
				{URI: "cpe:2.3:a:php:php:7.3.33:*:*:*:*:*:*:*", UseJVN: true},
				{URI: "cpe:/a:openssl:openssl:1.1.1w", UseJVN: true},
			},
		},
		{
			name: "cpeNames of another server are ignored",
			in: func() models.ScanResult {
				r := models.ScanResult{ServerName: "host1"}
				r.Config.Scan.Servers = map[string]config.ServerInfo{
					"host2": {CpeNames: []string{"cpe:2.3:a:php:php:7.3.33:*:*:*:*:*:*:*"}},
				}
				return r
			}(),
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cpesFromRequest(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cpesFromRequest() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
