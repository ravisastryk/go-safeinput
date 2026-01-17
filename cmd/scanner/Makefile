.PHONY: scan build clean report

# Build scanner
build:
	go build -o bin/scanner .

# Run scan and save results
scan: build
	@if [ -z "$$GITHUB_TOKEN" ]; then \
		echo "ERROR: Set GITHUB_TOKEN first"; \
		echo "  export GITHUB_TOKEN=your_token"; \
		exit 1; \
	fi
	./bin/scanner -output metrics/scan_$(shell date +%Y%m%d).json

# Generate markdown report from latest scan
report:
	@latest=$$(ls -t metrics/scan_*.json 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then \
		echo "No scan results found. Run 'make scan' first"; \
		exit 1; \
	fi; \
	echo "# CWE-502 Impact Report" > metrics/REPORT.md; \
	echo "" >> metrics/REPORT.md; \
	echo "Generated: $$(date)" >> metrics/REPORT.md; \
	echo "" >> metrics/REPORT.md; \
	echo "## Summary" >> metrics/REPORT.md; \
	echo "" >> metrics/REPORT.md; \
	echo "| Metric | Value |" >> metrics/REPORT.md; \
	echo "|--------|-------|" >> metrics/REPORT.md; \
	echo "| Vulnerable Instances | $$(jq '.total_vulnerable' $$latest) |" >> metrics/REPORT.md; \
	echo "| Stars Affected | $$(jq '.total_stars' $$latest) |" >> metrics/REPORT.md; \
	echo "| Forks Affected | $$(jq '.total_forks' $$latest) |" >> metrics/REPORT.md; \
	echo "" >> metrics/REPORT.md; \
	echo "## By Pattern" >> metrics/REPORT.md; \
	echo "" >> metrics/REPORT.md; \
	echo "| Pattern | Count | Severity |" >> metrics/REPORT.md; \
	echo "|---------|-------|----------|" >> metrics/REPORT.md; \
	jq -r '.results[] | "| \(.pattern.name) | \(.count) | \(.pattern.severity) |"' $$latest >> metrics/REPORT.md; \
	echo "" >> metrics/REPORT.md; \
	echo "Report saved to metrics/REPORT.md"

# Quick scan to stdout
quick:
	@if [ -z "$$GITHUB_TOKEN" ]; then \
		echo "ERROR: Set GITHUB_TOKEN"; \
		exit 1; \
	fi
	go run .

# Setup metrics directory
setup:
	mkdir -p metrics bin

# Clean
clean:
	rm -rf bin metrics/*.json
