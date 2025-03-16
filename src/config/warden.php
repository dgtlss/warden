<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Notification Settings
    |--------------------------------------------------------------------------
    |
    | Configure where Warden should send security audit notifications:
    | - webhook_url: Slack, Discord, or custom webhook endpoint
    | - email_recipients: Comma-separated list of email addresses
    |
    | Example:
    | WARDEN_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    | WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
    |
    */

    'webhook_url' => env('WARDEN_WEBHOOK_URL', null),
    'email_recipients' => env('WARDEN_EMAIL_RECIPIENTS', null),

    /*
    |--------------------------------------------------------------------------
    | Security Audit Configuration
    |--------------------------------------------------------------------------
    |
    | Define environment variables that should be checked during security audits.
    | These keys are considered security-critical and should be properly set
    | in your production environment.
    |
    | Add your own sensitive keys based on your application's requirements.
    | The check will fail if these keys are missing from your .env file,
    | encouraging proper security configuration from the start.
    |
    | Example key formats:
    | - Database: DB_PASSWORD
    | - Email: SMTP_PASSWORD, MAILGUN_SECRET
    | - Payment: STRIPE_SECRET_KEY, PAYPAL_SECRET
    | - Cloud: AWS_SECRET_KEY, GOOGLE_CLOUD_KEY
    |
    */
   
    'sensitive_keys' => [
       // Add your sensitive keys here
    ],
];
