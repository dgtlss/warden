
# Warden

Warden is a Laravel package that performs security audits on your composer dependencies and provides automated notifications for any discovered vulnerabilities. 

It is designed to fail your preferred CI/CD pipeline when vulnerabilities are detected, ensuring that security issues are addressed promptly.

## Installation

You can install the package via composer:

```bash
composer require dgtlss/warden
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag="warden-config"
```

This will create a `config/warden.php` file in your application.

### Environment Variables

Add the following variables to your `.env` file:

```env
# Webhook Configuration
WARDEN_WEBHOOK_URL=
WARDEN_EMAIL_RECIPIENTS=email1@example.com,email2@example.com

# Mail Configuration
WARDEN_MAIL_TRANSPORT=smtp
WARDEN_MAIL_HOST=smtp.example.com
WARDEN_MAIL_PORT=587
WARDEN_MAIL_USERNAME=
WARDEN_MAIL_PASSWORD=
WARDEN_MAIL_ENCRYPTION=tls
WARDEN_MAIL_FROM_ADDRESS=warden@example.com
WARDEN_MAIL_FROM_NAME="Warden Alerts"
```

## Usage

Warden provides a simple command to run security audits:

```bash
php artisan warden:audit
```

### Command Options

- `--silent`: Run the audit without sending notifications
```bash
php artisan warden:audit --silent
```

### Exit Codes

The command returns different exit codes based on the audit results:
- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected
- `2`: Audit process failed to run

## Notifications

Warden supports two types of notifications:

### 1. Webhook Notifications
Configure `WARDEN_WEBHOOK_URL` in your `.env` file to receive webhook notifications. The webhook will receive a POST request with the audit report in the request body.

### 2. Email Notifications
Configure the email recipients and SMTP settings in your `.env` file to receive email notifications. Multiple recipients can be specified as a comma-separated list in `WARDEN_EMAIL_RECIPIENTS`.

## Report Format

The audit report includes:
- Package name
- Vulnerability title
- CVE identifier
- Reference link
- Affected versions

## CI/CD Integration

Warden is designed to fail your CI/CD pipeline when vulnerabilities are detected. This ensures that security issues are addressed promptly.

Example GitHub Actions workflow:

```yaml
steps:
  - name: Security Audit
    run: php artisan warden:audit
    continue-on-error: false
```

Example Chipper CI workflow:

```yaml
tasks:
  - name: Install Dependencies
    script: composer install --no-interaction --prefer-dist

  - name: Run Warden Audit
    script: php artisan warden:audit --silent
```

## License

This package is open source and released under the MIT License.

## Contributing

We welcome contributions to improve the package. Please see our [CONTRIBUTING GUIDELINES](CONTRIBUTING.md) for guidelines on how to submit improvements and bug fixes.

## Donate

If you find this package useful, please consider donating to support its development and maintenance.
