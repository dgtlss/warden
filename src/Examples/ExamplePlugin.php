<?php

namespace Dgtlss\Warden\Examples;

use Dgtlss\Warden\Plugins\AbstractPlugin;

/**
 * Example plugin demonstrating how to extend Warden.
 *
 * This plugin shows how to:
 * - Create a custom audit service (DockerAuditService)
 * - Create a custom notification channel (WebhookChannel)
 * - Register them with Warden
 *
 * To create your own plugin:
 *
 * 1. Create a class extending AbstractPlugin
 * 2. Set the $name, $version, and $description properties
 * 3. Override audits() to return your audit service classes
 * 4. Override channels() to return your notification channel classes
 * 5. Register your plugin in config/warden.php:
 *
 *    'plugins' => [
 *        'registered' => [
 *            \App\Warden\MyPlugin::class,
 *        ],
 *    ],
 *
 * Or for package distribution, add to your composer.json:
 *
 *    "extra": {
 *        "warden": {
 *            "plugin": "Vendor\\Package\\MyPlugin"
 *        }
 *    }
 */
class ExamplePlugin extends AbstractPlugin
{
    /**
     * The plugin name (kebab-case, unique identifier).
     */
    protected string $name = 'warden-example';

    /**
     * The plugin version (semantic versioning).
     */
    protected string $version = '1.0.0';

    /**
     * A brief description of what this plugin does.
     */
    protected string $description = 'Example Warden plugin with Docker security audits and custom webhook notifications';

    /**
     * The plugin author.
     */
    protected ?string $author = 'Warden Team';

    /**
     * Return the audit service classes this plugin provides.
     *
     * Each class must implement Dgtlss\Warden\Contracts\AuditService.
     *
     * @return array<int, class-string>
     */
    public function audits(): array
    {
        return [
            DockerAuditService::class,
        ];
    }

    /**
     * Return the notification channel classes this plugin provides.
     *
     * Each class must implement Dgtlss\Warden\Contracts\NotificationChannel.
     *
     * @return array<int, class-string>
     */
    public function channels(): array
    {
        return [
            WebhookChannel::class,
        ];
    }

    /**
     * Return the Artisan command classes this plugin provides.
     *
     * Each class must extend Illuminate\Console\Command.
     *
     * @return array<int, class-string>
     */
    public function commands(): array
    {
        return [
            // Add your custom commands here
            // ExampleCommand::class,
        ];
    }
}
