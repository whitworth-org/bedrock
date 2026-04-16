package web

import "testing"

func TestAltSvcAdvertisesH3(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{
			name:   "empty header",
			header: "",
			want:   false,
		},
		{
			name:   "h3 only",
			header: `h3=":443"`,
			want:   true,
		},
		{
			name:   "h3 with ma parameter",
			header: `h3=":443"; ma=86400`,
			want:   true,
		},
		{
			name:   "draft h3-29",
			header: `h3-29=":443"; ma=86400`,
			want:   true,
		},
		{
			name:   "h3 alongside h2 (multi-value)",
			header: `h2=":443"; ma=86400, h3=":443"; ma=86400`,
			want:   true,
		},
		{
			name:   "case-insensitive protocol id",
			header: `H3=":443"`,
			want:   true,
		},
		{
			name:   "only h2 (HTTP/2 alt-svc, no HTTP/3)",
			header: `h2=":443"; ma=86400`,
			want:   false,
		},
		{
			name:   "clear withdraws all alternatives",
			header: "clear",
			want:   false,
		},
		{
			name:   "h3 with port-only authority (no host)",
			header: `h3=":8443"; ma=3600; persist=1`,
			want:   true,
		},
		{
			name: "h3 with cross-host alternative",
			// RFC 7838 §3 permits alt-authority to include a host.
			header: `h3="alt.example.com:443"; ma=600`,
			want:   true,
		},
		{
			name:   "lookalike protocol id",
			header: `h3x=":443"`,
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := altSvcAdvertisesH3(tc.header); got != tc.want {
				t.Errorf("altSvcAdvertisesH3(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
