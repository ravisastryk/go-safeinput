// Command scanner searches GitHub for CWE-502 vulnerable patterns
// and measures the impact of go-safeinput across the Go ecosystem.
//
// Usage:
//
//	export GITHUB_TOKEN=your_token
//	go run main.go
//	go run main.go -output results.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	githubAPI = "https://api.github.com"
	userAgent = "go-safeinput-scanner/1.0"
)

// Pattern defines a vulnerable code pattern to search
type Pattern struct {
	Name        string `json:"name"`
	Query       string `json:"query"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// SearchResult holds GitHub search results
type SearchResult struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		Repository struct {
			FullName        string `json:"full_name"`
			StargazersCount int    `json:"stargazers_count"`
			ForksCount      int    `json:"forks_count"`
			HTMLURL         string `json:"html_url"`
		} `json:"repository"`
	} `json:"items"`
}

// PatternResult holds results for a single pattern
type PatternResult struct {
	Pattern    Pattern `json:"pattern"`
	Count      int     `json:"count"`
	TopRepos   []Repo  `json:"top_repos"`
	SearchedAt string  `json:"searched_at"`
}

// Repo holds repository info
type Repo struct {
	Name  string `json:"name"`
	Stars int    `json:"stars"`
	Forks int    `json:"forks"`
	URL   string `json:"url"`
	File  string `json:"file"`
}

// Report holds the full scan report
type Report struct {
	GeneratedAt     string          `json:"generated_at"`
	Scanner         string          `json:"scanner"`
	ScannerRepo     string          `json:"scanner_repo"`
	TotalVulnerable int             `json:"total_vulnerable"`
	TotalStars      int             `json:"total_stars"`
	TotalForks      int             `json:"total_forks"`
	Results         []PatternResult `json:"results"`
}

var patterns = []Pattern{
	{
		Name:        "json-unmarshal-interface",
		Query:       `language:go "json.Unmarshal" "interface{}"`,
		Severity:    "HIGH",
		Description: "JSON deserialization into interface{}",
	},
	{
		Name:        "yaml-unmarshal-interface",
		Query:       `language:go "yaml.Unmarshal" "interface{}"`,
		Severity:    "HIGH",
		Description: "YAML deserialization into interface{}",
	},
	{
		Name:        "json-decoder-interface",
		Query:       `language:go "json.NewDecoder" "interface{}"`,
		Severity:    "HIGH",
		Description: "JSON decoder into interface{}",
	},
	{
		Name:        "xml-unmarshal-interface",
		Query:       `language:go "xml.Unmarshal" "interface{}"`,
		Severity:    "HIGH",
		Description: "XML deserialization into interface{}",
	},
	{
		Name:        "yaml-v2-import",
		Query:       `language:go "gopkg.in/yaml.v2"`,
		Severity:    "MEDIUM",
		Description: "Using yaml.v2 (vulnerable to custom tags)",
	},
}

func main() {
	outputFile := flag.String("output", "", "Output JSON file (default: stdout)")
	flag.Parse()

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "ERROR: GITHUB_TOKEN environment variable required")
		fmt.Fprintln(os.Stderr, "Get one at: https://github.com/settings/tokens")
		os.Exit(1)
	}

	report := runScan(token)
	if err := outputReport(report, *outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func runScan(token string) Report {
	fmt.Fprintln(os.Stderr, "=== go-safeinput Impact Scanner ===")
	fmt.Fprintln(os.Stderr, "")

	report := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Scanner:     "go-safeinput-scanner",
		ScannerRepo: "https://github.com/ravisastryk/go-safeinput",
		Results:     make([]PatternResult, 0),
	}

	client := &http.Client{Timeout: 30 * time.Second}
	seenRepos := make(map[string]bool)

	for i, pattern := range patterns {
		fmt.Fprintf(os.Stderr, "[%d/%d] Scanning: %s\n", i+1, len(patterns), pattern.Name)

		result, err := searchGitHub(client, token, pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
			continue
		}

		fmt.Fprintf(os.Stderr, "  Found: %d instances\n", result.Count)
		report.Results = append(report.Results, result)
		report.TotalVulnerable += result.Count

		for _, repo := range result.TopRepos {
			if !seenRepos[repo.Name] {
				seenRepos[repo.Name] = true
				report.TotalStars += repo.Stars
				report.TotalForks += repo.Forks
			}
		}

		// Rate limit: 10 requests per minute for code search
		time.Sleep(6 * time.Second)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "=== Summary ===")
	fmt.Fprintf(os.Stderr, "Total vulnerable instances: %d\n", report.TotalVulnerable)
	fmt.Fprintf(os.Stderr, "Total stars affected: %d\n", report.TotalStars)
	fmt.Fprintf(os.Stderr, "Total forks affected: %d\n", report.TotalForks)
	fmt.Fprintln(os.Stderr, "")

	return report
}

func outputReport(report Report, outputFile string) error {
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, output, 0600); err != nil {
			return fmt.Errorf("writing file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Results saved to: %s\n", outputFile)
	} else {
		fmt.Println(string(output))
	}

	return nil
}

func searchGitHub(client *http.Client, token string, pattern Pattern) (PatternResult, error) {
	result := PatternResult{
		Pattern:    pattern,
		SearchedAt: time.Now().UTC().Format(time.RFC3339),
		TopRepos:   make([]Repo, 0),
	}

	// Build URL
	searchURL := fmt.Sprintf("%s/search/code?q=%s&per_page=10",
		githubAPI, url.QueryEscape(pattern.Query))

	req, err := http.NewRequestWithContext(context.Background(), "GET", searchURL, nil)
	if err != nil {
		return result, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return result, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var searchResult SearchResult
	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return result, err
	}

	result.Count = searchResult.TotalCount

	// Track unique repos to avoid duplicate API calls
	seenRepos := make(map[string]bool)

	for _, item := range searchResult.Items {
		repoName := item.Repository.FullName

		// Skip if we already have this repo
		if seenRepos[repoName] {
			continue
		}
		seenRepos[repoName] = true

		// Get accurate star/fork counts from repo API
		stars := item.Repository.StargazersCount
		forks := item.Repository.ForksCount

		// If Code Search API didn't return counts, fetch from repo API
		if stars == 0 && forks == 0 {
			repoData, err := fetchRepoDetails(client, token, repoName)
			if err == nil {
				stars = repoData.StargazersCount
				forks = repoData.ForksCount
			}
		}

		result.TopRepos = append(result.TopRepos, Repo{
			Name:  repoName,
			Stars: stars,
			Forks: forks,
			URL:   item.Repository.HTMLURL,
			File:  item.Path,
		})
	}

	return result, nil
}

// RepoDetails holds repository metadata
type RepoDetails struct {
	StargazersCount int `json:"stargazers_count"`
	ForksCount      int `json:"forks_count"`
}

// fetchRepoDetails gets accurate repository metadata
func fetchRepoDetails(client *http.Client, token, repoName string) (*RepoDetails, error) {
	repoURL := fmt.Sprintf("%s/repos/%s", githubAPI, repoName)

	req, err := http.NewRequestWithContext(context.Background(), "GET", repoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var repoDetails RepoDetails
	if err := json.NewDecoder(resp.Body).Decode(&repoDetails); err != nil {
		return nil, err
	}

	return &repoDetails, nil
}
