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
    | Sensitive Keys
    |--------------------------------------------------------------------------
    |
    | These are the keys that we want to check for in the .env file.
    | If they are not found, we will add a finding to your report.
    |
    */
   
    'sensitive_keys' => [
        'DB_PASSWORD',
        'MAIL_PASSWORD',
        'STRIPE_API_KEY',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
    ],
];
