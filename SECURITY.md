# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PadmaVue.ai, please report it responsibly:

1. **Email**: Send details to [security@padmavue.ai](mailto:security@padmavue.ai)
2. **GitHub Security Advisory**: Use [GitHub's private vulnerability reporting](https://github.com/yourusername/PadmaVue.ai/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution**: Depends on severity (critical: ASAP, high: 30 days, medium/low: 90 days)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Best Practices

When deploying PadmaVue.ai:

1. **Never expose to public internet** without authentication
2. **Change default secrets** in `.env` files
3. **Use HTTPS** in production
4. **Keep dependencies updated**: `pip install --upgrade -r requirements.txt`
5. **Review AI provider data policies** before sending sensitive data

## Scope

This security policy covers:
- The PadmaVue.ai application code
- Default configurations
- Official Docker images

Out of scope:
- Third-party dependencies (report to their maintainers)
- User-deployed infrastructure misconfigurations
