<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Warden Configuration
    |--------------------------------------------------------------------------
    |
    | Set the webhook URL and email recipients for notifications.
    | These can be set here or in the .env file.
    |
    */

    'webhook_url' => env('WARDEN_WEBHOOK_URL', null),

    'email_recipients' => env('WARDEN_EMAIL_RECIPIENTS', null), // Comma-separated emails

    /*
    |--------------------------------------------------------------------------
    | Custom SMTP Configuration
    |--------------------------------------------------------------------------
    |
    | If you wish to use different SMTP settings for Warden's email notifications,
    | you can specify them here or in your .env file.
    |
    */

    'mail' => [
        'transport' => env('WARDEN_MAIL_TRANSPORT', 'smtp'),
        'host' => env('WARDEN_MAIL_HOST', 'smtp.example.com'),
        'port' => env('WARDEN_MAIL_PORT', 587),
        'username' => env('WARDEN_MAIL_USERNAME', null),
        'password' => env('WARDEN_MAIL_PASSWORD', null),
        'encryption' => env('WARDEN_MAIL_ENCRYPTION', 'tls'),
        'from_address' => env('WARDEN_MAIL_FROM_ADDRESS', 'warden@example.com'),
        'from_name' => env('WARDEN_MAIL_FROM_NAME', 'Warden Alerts'),
    ],

];
