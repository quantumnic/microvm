# Contributing to microvm

Thanks for your interest! Here's how to get started.

## Getting Started

1. Fork the repo
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Run clippy: `cargo clippy`
6. Commit with a clear message
7. Open a PR

## Code Style

- Follow standard Rust conventions (`rustfmt`)
- Use `cargo clippy` — no warnings
- Add tests for new functionality
- Document public APIs

## Areas to Contribute

- **CPU**: Instruction correctness, missing extensions (F/D)
- **Devices**: VirtIO implementations, new device types
- **Testing**: RISC-V compliance tests, integration tests
- **Docs**: Examples, tutorials, architecture docs
- **Performance**: Profiling, optimization

## Reporting Issues

Use GitHub Issues. Include:
- What you expected
- What happened
- Steps to reproduce
- `microvm --version` output

## License

By contributing, you agree that your contributions will be licensed under MIT.
