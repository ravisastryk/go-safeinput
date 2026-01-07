# Contributing to go-safeinput

Thank you for your interest in contributing to go-safeinput! This document provides guidelines for contributing to this project.

## Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Goal

The main goal is to keep the `main` branch always releasable with stable, backward-compatible code.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check if the issue has already been reported in the [issue tracker](https://github.com/ravisastryk/go-safeinput/issues)
2. Verify the issue against the latest version of the library
3. Ensure the issue is actually related to this library and not user error

When creating a bug report, include:
- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Go version and operating system
- Code samples demonstrating the issue

### Suggesting Features

Feature suggestions are welcome! When suggesting a feature:
- Provide a detailed description of the feature
- Explain the use case and why it would be valuable
- Include example code showing how the feature would be used
- Consider if the feature aligns with the library's goal of zero external dependencies

### Contributing Code

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/go-safeinput.git
   cd go-safeinput
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature-name
   ```

3. **Set up your development environment**
   ```bash
   # Ensure you have Go 1.23+ installed
   go version

   # Install development tools
   make tools
   ```

4. **Make your changes**
   - Follow Go best practices and idioms
   - Use camelCase for naming
   - Add appropriate comments and documentation
   - Implement proper error handling
   - Maintain zero external dependencies (standard library only)

5. **Write tests**
   - Add tests for all new functionality
   - Ensure test coverage remains at 90% or higher
   - Run tests with race detection

6. **Run quality checks**
   ```bash
   # Format your code
   make fmt

   # Run linter
   make lint

   # Run tests
   make test

   # Run security checks
   make security
   ```

7. **Commit your changes**
   - Use clear, descriptive commit messages
   - Start with a capital letter
   - Use past tense ("Added feature" not "Add feature")
   - Reference related issues if applicable

   ```bash
   git commit -m "Added validation for special characters in SQL identifiers"
   ```

8. **Push to your fork**
   ```bash
   git push origin feature-name
   ```

9. **Open a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Ensure all CI checks pass

## Code Standards

### Testing Requirements

- **Minimum coverage**: 90% for all new code
- **Race detection**: All tests must pass with `-race` flag
- **Test naming**: Use descriptive names that explain what is being tested

```bash
# Run tests with coverage
make test

# Generate HTML coverage report
make coverage-html
```

### Linting Requirements

All code must pass `golangci-lint` with no errors:

```bash
make lint
```

### Code Conventions

- **Formatting**: Code must be formatted with `gofmt` and `goimports`
- **Naming**: Follow Go naming conventions (camelCase, no underscores)
- **Comments**: Export all public functions and types with documentation comments
- **Error handling**: Always check and handle errors appropriately
- **Dependencies**: Avoid external dependencies; use only the Go standard library

### Security

- Run security checks before submitting: `make security`
- Be mindful of potential vulnerabilities
- Never introduce code that could create security issues

## Local Development Commands

```bash
# Run all quality checks (lint + test)
make all

# Run tests with coverage verification
make test

# Run linter
make lint

# Run security scanners
make security

# Format code
make fmt

# Tidy dependencies
make tidy

# Generate HTML coverage report
make coverage-html

# Install development tools
make tools

# Clean build artifacts
make clean
```

## Pull Request Checklist

Before submitting your pull request, ensure:

- [ ] Code is formatted (`make fmt`)
- [ ] Linter passes with no errors (`make lint`)
- [ ] All tests pass (`make test`)
- [ ] Test coverage is at 90% or higher
- [ ] Security checks pass (`make security`)
- [ ] New code has comprehensive tests
- [ ] Public functions/types have documentation comments
- [ ] Commit messages are clear and descriptive
- [ ] No external dependencies were added
- [ ] Changes are backward compatible

## Questions or Need Help?

- Open an issue for questions about contributing
- Check existing issues and pull requests for similar discussions
- Refer to the [README](README.md) for project overview and usage

## License

By contributing to go-safeinput, you agree that your contributions will be licensed under the MIT License.
