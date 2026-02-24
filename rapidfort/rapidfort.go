package rapidfort

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	rapidfortDir  = "rapidfort"
	defaultRepoURL = "https://github.com/rapidfort/security-advisories.git"
	repoBranch    = "main"
	repoCloneDir  = "rapidfort-advisories" // subdir inside cacheDir
	repoOSPath    = "OS"                   // OS/{osName}/{package}.json inside the repo
)

// defaultSupportedOSes lists the OS subdirectories to ingest from the cloned repo.
var defaultSupportedOSes = []string{"ubuntu", "alpine"}

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithCacheDir(v string) option {
	return func(c *Updater) { c.cacheDir = v }
}

// WithRepoDir bypasses git clone and reads advisory files from this directory directly.
// Useful in tests or when the repo is already available locally.
func WithRepoDir(v string) option {
	return func(c *Updater) { c.repoDir = v }
}

// WithRepoURL overrides the git clone URL (e.g. to use SSH or inject a token).
func WithRepoURL(v string) option {
	return func(c *Updater) { c.repoURL = v }
}

// WithSupportedOSes overrides the list of OS directories to process (used in tests).
func WithSupportedOSes(oses []string) option {
	return func(c *Updater) { c.supportedOSes = oses }
}

// Updater clones the RapidFort security-advisories repo and writes per-codename
// per-package JSON files to vuln-list/rapidfort/{os}/{codename}/{package}.json.
type Updater struct {
	vulnListDir   string
	cacheDir      string
	repoDir       string // if set, skip git clone and read from here
	repoURL       string
	supportedOSes []string
}

func NewUpdater(options ...option) *Updater {
	repoURL := buildRepoURL()
	updater := &Updater{
		vulnListDir:   utils.VulnListDir(),
		cacheDir:      utils.CacheDir(),
		repoURL:       repoURL,
		supportedOSes: defaultSupportedOSes,
	}
	for _, opt := range options {
		opt(updater)
	}
	return updater
}

// buildRepoURL returns the clone URL, injecting GITHUB_TOKEN if available
// so private repos work in CI without SSH key setup.
func buildRepoURL() string {
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		return fmt.Sprintf("https://%s@github.com/rapidfort/security-advisories.git", token)
	}
	return defaultRepoURL
}

// Update clones (or pulls) the advisories repo, then processes all supported OSes.
func (u *Updater) Update() error {
	repoDir := u.repoDir
	if repoDir == "" {
		// Clone or pull into the cache directory.
		repoDir = filepath.Join(u.cacheDir, repoCloneDir)
		log.Printf("Cloning/pulling RapidFort security advisories into %s", repoDir)
		gc := git.Config{}
		if _, err := gc.CloneOrPull(u.repoURL, repoDir, repoBranch, false); err != nil {
			return xerrors.Errorf("failed to clone/pull RapidFort advisory repo: %w", err)
		}
	}

	outDir := filepath.Join(u.vulnListDir, rapidfortDir)
	log.Printf("Removing old RapidFort data at %s", outDir)
	if err := os.RemoveAll(outDir); err != nil {
		return xerrors.Errorf("failed to remove old RapidFort directory: %w", err)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return xerrors.Errorf("failed to create RapidFort output directory: %w", err)
	}

	for _, osName := range u.supportedOSes {
		srcDir := filepath.Join(repoDir, repoOSPath, osName)
		if ok, _ := utils.Exists(srcDir); !ok {
			log.Printf("warn: %s not found in advisory repo, skipping", srcDir)
			continue
		}
		log.Printf("Processing RapidFort advisories for %s...", osName)
		if err := u.processOS(outDir, osName, srcDir); err != nil {
			return xerrors.Errorf("failed to process %s advisories: %w", osName, err)
		}
	}
	return nil
}

// processOS walks all *.json files in srcDir, parses each SourcePackageAdvisory,
// and writes split per-codename output files under outDir/{osName}/.
func (u *Updater) processOS(outDir, osName, srcDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return xerrors.Errorf("failed to read %s: %w", srcDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(srcDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("warn: failed to read %s: %v", filePath, err)
			continue
		}

		var src SourcePackageAdvisory
		if err := json.Unmarshal(data, &src); err != nil {
			log.Printf("warn: failed to parse %s: %v", filePath, err)
			continue
		}

		if src.PackageName == "" {
			log.Printf("warn: missing package_name in %s, skipping", filePath)
			continue
		}

		if err := u.saveAdvisory(outDir, osName, src); err != nil {
			return xerrors.Errorf("failed to save advisory for %s/%s: %w", osName, src.PackageName, err)
		}
	}
	return nil
}

// saveAdvisory splits a SourcePackageAdvisory by codename and writes one file per codename.
// Output path: {outDir}/{osName}/{codename}/{packageName}.json
func (u *Updater) saveAdvisory(outDir, osName string, src SourcePackageAdvisory) error {
	for codename, cveMap := range src.Advisory {
		if len(cveMap) == 0 {
			continue
		}
		pkg := PackageAdvisory{
			PackageName:    src.PackageName,
			DistroCodename: codename,
			Advisories:     cveMap,
		}
		filePath := filepath.Join(outDir, osName, codename, fmt.Sprintf("%s.json", src.PackageName))
		if err := utils.Write(filePath, pkg); err != nil {
			return xerrors.Errorf("failed to write %s: %w", filePath, err)
		}
		log.Printf("Saved %s", filePath)
	}
	return nil
}
