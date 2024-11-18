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
];
