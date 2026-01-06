# Contributing to go-safeinput

Thanks for your interest in contributing! This project welcomes contributions from everyone.

## Getting Started

1. **Fork the repository** on GitHub

2. **Clone your fork**
   ```bash
   git clone https://github.com/ravisastryk/go-safeinput.git
   cd go-safeinput
   ```

3. **Set up your environment**
   ```bash
   # Ensure you have Go 1.24+ installed
   go version

   # Download dependencies
   go mod download
   ```

## Making Changes

1. **Create a branch**
   ```bash
   git checkout -b your-feature-name
   ```

2. **Make your changes** and ensure they follow Go best practices

3. **Format your code**
   ```bash
   gofmt -w .
   ```

4. **Run the linter**
   ```bash
   make lint
   # or
   golangci-lint run
   ```

5. **Run tests**
   ```bash
   make test
   # or
   go test -v -race ./...
   ```

## Code Guidelines

- **Format**: All code must be formatted with `gofmt`
- **Lint**: Code must pass `golangci-lint` with no errors
- **Tests**: Add tests for new functionality
- **Coverage**: Maintain 90%+ test coverage
- **Dependencies**: Avoid external dependencies when possible (this library uses only the Go standard library)

## Testing Your Changes

```bash
# Run all tests with race detection
go test -v -race ./...

# Check coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

## Submitting a Pull Request

1. **Ensure all checks pass**
   ```bash
   make lint
   make test
   ```

2. **Commit your changes** with a clear message
   ```bash
   git commit -m "Add feature X"
   ```

3. **Push to your fork**
   ```bash
   git push origin your-feature-name
   ```

4. **Open a Pull Request** against the `main` branch

### PR Checklist

- [ ] Code is formatted (`gofmt`)
- [ ] Linter passes (`golangci-lint run`)
- [ ] Tests pass (`go test -race ./...`)
- [ ] Coverage remains at 90%+
- [ ] New code has tests
- [ ] Commit messages are clear

## Questions?

Feel free to open an issue if you have questions or need help getting started.