<?php

namespace Dgtlss\Warden\Services\Dependencies;

use Dgtlss\Warden\Abstracts\AbstractAuditDependency;

class PhpExtensionDependency extends AbstractAuditDependency
{
    protected string $extension;

    public function __construct(string $extension, int $priority = 100)
    {
        parent::__construct("php-extension-{$extension}", 'php-extension', $priority);
        $this->extension = $extension;
    }

    /**
     * Check if the dependency is satisfied.
     *
     * @return bool
     */
    public function isSatisfied(): bool
    {
        return extension_loaded($this->extension);
    }

    /**
     * Get the reason why the dependency is not satisfied.
     *
     * @return string|null
     */
    public function getUnsatisfiedReason(): ?string
    {
        if ($this->isSatisfied()) {
            return null;
        }

        return "PHP extension '{$this->extension}' is not loaded. Please install or enable it.";
    }

    /**
     * Attempt to resolve the dependency.
     *
     * @return bool
     */
    public function resolve(): bool
    {
        // PHP extensions cannot be automatically resolved at runtime
        return false;
    }

    /**
     * Get configuration options for this dependency.
     *
     * @return array
     */
    public function getConfigOptions(): array
    {
        return [
            'extension' => [
                'type' => 'string',
                'description' => 'The PHP extension name',
                'required' => true,
            ],
            'installation_hint' => [
                'type' => 'string',
                'description' => 'Hint on how to install the extension',
                'default' => "Install the {$this->extension} PHP extension",
            ]
        ];
    }
}