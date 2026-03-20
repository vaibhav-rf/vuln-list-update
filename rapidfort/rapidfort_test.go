package rapidfort

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name      string
		repoDir   string            // directory that stands in for the cloned repo
		wantErr   string
		wantFiles []string // relative paths under tmpDir/rapidfort that should exist
	}{
		{
			name:    "happy path",
			repoDir: "testdata/repo",
			wantFiles: []string{
				"ubuntu/20.04/curl.json",
				"redhat/9/curl.json",
			},
		},
		{
			name:    "invalid JSON is skipped without error",
			repoDir: "testdata/repo_invalid",
		},
		{
			name:    "missing OS directory is skipped without error",
			repoDir: "testdata/repo_empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			updater := NewUpdater(
				WithVulnListDir(tmpDir),
				WithRepoDir(tt.repoDir),
				WithSupportedOSes([]string{"ubuntu", "redhat"}),
			)

			err := updater.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			for _, relPath := range tt.wantFiles {
				actualPath := filepath.Join(tmpDir, rapidfortDir, relPath)
				actual, err := os.ReadFile(actualPath)
				require.NoError(t, err, "expected output file not found: %s", relPath)

				goldenPath := filepath.Join("testdata", "happy", relPath)
				if *update {
					require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0755))
					require.NoError(t, os.WriteFile(goldenPath, actual, 0644))
				}

				expected, err := os.ReadFile(goldenPath)
				require.NoError(t, err, "golden file not found: %s", goldenPath)

				assert.JSONEq(t, string(expected), string(actual), "mismatch for %s", relPath)
			}
		})
	}
}
