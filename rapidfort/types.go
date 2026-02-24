package rapidfort

// SourcePackageAdvisory represents the format of a file in the security-advisories GitHub repo.
// e.g. OS/ubuntu/curl.json or OS/debian/curl.json
type SourcePackageAdvisory struct {
	PackageName string                        `json:"package_name"`
	Advisory    map[string]map[string]CVEEntry `json:"advisory"` // codename -> cveID -> CVEEntry
}

// CVEEntry represents a single CVE advisory entry within a distro release.
type CVEEntry struct {
	CVEID       string  `json:"cve_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Status      string  `json:"status"` // "fixed" or "open"
	Events      []Event `json:"events"`
}

// Event represents a version range event (introduced and optionally fixed).
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// PackageAdvisory is the normalized form written to vuln-list, one file per OS codename per package.
// Output path: vuln-list/rapidfort/{os}/{codename}/{package_name}.json
type PackageAdvisory struct {
	PackageName    string              `json:"package_name"`
	DistroCodename string              `json:"distro_codename"`
	Advisories     map[string]CVEEntry `json:"advisories"` // cveID -> CVEEntry
}

// GitHubContentItem represents one item returned by the GitHub Contents REST API.
type GitHubContentItem struct {
	Name        string `json:"name"`
	Type        string `json:"type"`         // "file" or "dir"
	DownloadURL string `json:"download_url"` // URL to fetch raw file content
}
