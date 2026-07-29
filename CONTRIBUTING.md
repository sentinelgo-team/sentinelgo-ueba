# Contributing to SentinelGo

Thank you for your interest in contributing to SentinelGo.

## Development Setup

```bash
git clone https://github.com/sentinelgo/sentinelgo-ueba.git
cd sentinelgo-ueba
go mod tidy
make build
make test
```

## Branch Strategy

- `main` — Production-ready releases
- `develop` — Integration branch
- `feature/*` — Feature branches
- `bugfix/*` — Bug fixes

## Pull Request Process

1. Create a feature branch from `develop`
2. Implement the change
3. Write or update tests
4. Ensure all tests pass: `make test`
5. Ensure code is formatted: `make fmt`
6. Submit a pull request

## Commit Messages

Follow conventional commits:

```
feat(detection): add new credential dumping rule
fix(parser): handle empty timestamp in syslog
docs(readme): update installation instructions
test(scoring): add boundary value tests
```

## Code Standards

- Follow Go formatting (`gofmt`)
- Use descriptive names
- Handle errors explicitly
- Write tests for new functionality
- Keep functions focused and small

## Adding Detection Rules

1. Create a YAML file in `rules/`:

```yaml
id: "DET-XXX"
name: "Rule Name"
description: "What this rule detects."
enabled: true
severity: "high"
confidence: 0.80
mitre:
  technique: "TXXXX"
  tactic: "Tactic Name"
conditions:
  event_category: "authentication"
  event_outcome: "failure"
  threshold: 5
  window_minutes: 5
recommendations:
  - "Action to take."
```

2. Validate: `sentinelgo rules validate`
3. Test against sample data
4. Submit PR with test evidence

## Testing

```bash
make test          # All tests
make bench         # Benchmarks
make coverage      # Coverage report
```

## Questions?

Open an issue for questions, feature requests, or bug reports.
