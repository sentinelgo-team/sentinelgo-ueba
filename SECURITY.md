# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in SentinelGo, please report it responsibly.

**Do not** open a public issue for security vulnerabilities.

Instead, contact the maintainers privately with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if available)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Security Practices

SentinelGo follows these security principles:

- No hard-coded secrets
- Input validation on all external data
- Minimal dependencies
- Regular dependency review
- Structured error handling (no sensitive data in errors)
- Least-privilege execution model

## Scope

This policy applies to the SentinelGo codebase and official distributions. It does not cover:

- Third-party integrations
- User-created detection rules
- Custom deployments
- Infrastructure hosting the tool
