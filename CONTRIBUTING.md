# Contributing to IronClaw

Thank you for your interest in contributing to IronClaw! Security is our top priority, so please read these guidelines carefully.

## Code of Conduct

By participating, you agree to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security-First Development

All contributions must maintain IronClaw's security posture:

1. **No implicit trust** — Every external input must be validated
2. **Deny by default** — New features should require explicit opt-in
3. **Defense in depth** — Security should not rely on a single mechanism
4. **Minimal dependencies** — Every new dependency increases attack surface

## How to Contribute

### Reporting Bugs

- Use GitHub Issues for non-security bugs
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`cargo test`)
5. Run security checks (`cargo audit`)
6. Submit a pull request

### Code Standards

- **Rust edition**: 2021
- **Formatting**: `cargo fmt`
- **Linting**: `cargo clippy -- -D warnings`
- **Tests**: All public functions must have tests
- **Documentation**: All public types and functions must have doc comments

### Security Review Checklist

Before submitting a PR, verify:

- [ ] No hardcoded credentials or secrets
- [ ] All user input is validated
- [ ] All filesystem paths are canonicalized and checked against deny list
- [ ] All network requests use TLS
- [ ] All cryptographic operations use audited libraries
- [ ] Error messages do not leak sensitive information
- [ ] New tools have proper risk classification
- [ ] New tools declare required RBAC permissions
- [ ] Audit log entries are added for security-relevant events
- [ ] PII redaction patterns are updated if new data types are handled

## Architecture Guidelines

### Adding a New Tool

1. Implement the `Tool` trait in `src/core/tool.rs`
2. Set an appropriate `risk_level()`
3. Declare `required_permissions()`
4. Add argument validation in `validate_args()`
5. Register in the tool registry
6. Add configuration options
7. Write security tests

### Adding a New Provider

1. Implement the `Provider` trait in `src/providers/mod.rs`
2. Never log API keys (scrub from error messages)
3. Validate all responses
4. Add to `ProviderFactory`
5. Write integration tests

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
