# Warden

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![Total Downloads](https://img.shields.io/packagist/dt/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![License](https://img.shields.io/packagist/l/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)

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
```

```env
# Email Recipients Configuration
WARDEN_EMAIL_RECIPIENTS=email1@example.com,email2@example.com
```

## Available Audits

Warden performs several security audits on your Laravel application:

### 1. Composer Dependencies Audit
Checks your PHP dependencies for known security vulnerabilities using the `composer audit` command.

### 2. NPM Dependencies Audit
When enabled with the `--npm` flag, checks your JavaScript dependencies for known security vulnerabilities using `npm audit`.

### 3. Environment Configuration Audit
Verifies your environment configuration for security best practices:
- Checks for presence of `.env` file
- Ensures `.env` is properly gitignored
- Validates presence of critical environment variables
- Identifies potentially sensitive information

### 4. Storage Permissions Audit
Validates directory permissions for critical Laravel paths:
- `storage/framework`
- `storage/logs`
- `bootstrap/cache`
- Ensures proper write permissions
- Identifies missing or incorrectly configured directories

### 5. Configuration Security Audit
Examines your Laravel configuration for security issues:
- Debug mode status
- Session security settings
- CSRF protection
- Other common security misconfigurations

## Additional Arguments

### --ignore-abandoned

This flag will ignore abandoned packages in the warden audit. This is useful if you are using warden in a CI/CD pipeline and you want to ignore abandoned packages without failing the deployment. Particularly useful for Laravel packages that have abandoned packages as dependencies.

## Usage

### Basic Audit
```bash
php artisan warden:audit
```

### Including NPM Audit
```bash
php artisan warden:audit --npm
```

### Silent Mode (No Notifications)
```bash
php artisan warden:audit --silent
```

## Understanding Audit Results

The audit command will return different status codes:
- `0`: No vulnerabilities or issues found
- `1`: Vulnerabilities or security issues detected
- `2`: One or more audit processes failed to run

### Severity Levels

Findings are categorized by severity:
- `critical`: Requires immediate attention
- `high`: Should be addressed as soon as possible
- `medium`: Should be reviewed and fixed
- `low`: Minor security concerns
- `error`: Audit process or configuration errors

## Notification Format

When notifications are enabled, the report includes:
- Audit type (composer, npm, environment, storage, or configuration)
- Issue details specific to each audit type
- Severity level
- Remediation suggestions where applicable

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
