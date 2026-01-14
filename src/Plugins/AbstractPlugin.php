<?php

namespace Dgtlss\Warden\Plugins;

use Dgtlss\Warden\Contracts\WardenPlugin;
use Dgtlss\Warden\Services\PluginManager;

/**
 * Base class for Warden plugins.
 *
 * Provides sensible defaults so plugins only need to override
 * the methods relevant to their functionality.
 *
 * @example
 * ```php
 * class MyPlugin extends AbstractPlugin
 * {
 *     protected string $name = 'my-plugin';
 *     protected string $version = '1.0.0';
 *     protected string $description = 'My custom security audits';
 *
 *     public function audits(): array
 *     {
 *         return [
 *             MyCustomAudit::class,
 *             AnotherAudit::class,
 *         ];
 *     }
 * }
 * ```
 */
abstract class AbstractPlugin implements WardenPlugin
{
    /**
     * The plugin name (kebab-case).
     */
    protected string $name = 'unnamed-plugin';

    /**
     * The plugin version (semantic versioning).
     */
    protected string $version = '1.0.0';

    /**
     * The plugin description.
     */
    protected string $description = '';

    /**
     * The plugin author.
     */
    protected ?string $author = null;

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function version(): string
    {
        return $this->version;
    }

    /**
     * {@inheritdoc}
     */
    public function register(PluginManager $manager): void
    {
        // Override in subclass if needed
    }

    /**
     * {@inheritdoc}
     */
    public function boot(): void
    {
        // Override in subclass if needed
    }

    /**
     * {@inheritdoc}
     */
    public function audits(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function channels(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function commands(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function metadata(): array
    {
        return [
            'name' => $this->name(),
            'version' => $this->version(),
            'description' => $this->description,
            'author' => $this->author,
        ];
    }
}
