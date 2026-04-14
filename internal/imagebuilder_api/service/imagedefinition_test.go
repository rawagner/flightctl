package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNextVersion(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		lastVersion string
		want        string
		wantErr     bool
	}{
		{
			name:        "When no prior build exists it should use patch 0",
			pattern:     "1.0.x",
			lastVersion: "",
			want:        "1.0.0",
		},
		{
			name:        "When a prior build exists it should increment patch by 1",
			pattern:     "1.0.x",
			lastVersion: "1.0.0",
			want:        "1.0.1",
		},
		{
			name:        "When patch is non-zero it should increment correctly",
			pattern:     "1.0.x",
			lastVersion: "1.0.5",
			want:        "1.0.6",
		},
		{
			name:        "When major/minor differ in pattern it should use pattern's major/minor",
			pattern:     "2.3.x",
			lastVersion: "2.3.9",
			want:        "2.3.10",
		},
		{
			name:        "When pattern has 2 components it should return an error",
			pattern:     "1.0",
			lastVersion: "",
			wantErr:     true,
		},
		{
			name:        "When patch placeholder is not x it should return an error",
			pattern:     "1.0.0",
			lastVersion: "",
			wantErr:     true,
		},
		{
			name:        "When last version has invalid patch component it should return an error",
			pattern:     "1.0.x",
			lastVersion: "1.0.notanumber",
			wantErr:     true,
		},
		{
			name:        "When last version has wrong number of components it should return an error",
			pattern:     "1.0.x",
			lastVersion: "1.0",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NextVersion(tt.pattern, tt.lastVersion)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}
