<?php

namespace Dgtlss\Warden\Services\Dependencies;

use Dgtlss\Warden\Abstracts\AbstractAuditDependency;

class FileDependency extends AbstractAuditDependency
{
    protected string $path;
    protected bool $mustExist;
    protected bool $isDirectory;

    public function __construct(string $path, bool $mustExist = true, bool $isDirectory = false, int $priority = 100)
    {
        parent::__construct("file-" . str_replace('/', '-', trim($path, '/')), 'file', $priority);
        $this->path = $path;
        $this->mustExist = $mustExist;
        $this->isDirectory = $isDirectory;
    }

    /**
     * Check if the dependency is satisfied.
     *
     * @return bool
     */
    public function isSatisfied(): bool
    {
        $fullPath = base_path($this->path);
        
        if ($this->mustExist) {
            return $this->isDirectory ? is_dir($fullPath) : file_exists($fullPath);
        } else {
            return !file_exists($fullPath);
        }
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

        $fullPath = base_path($this->path);
        $type = $this->isDirectory ? 'Directory' : 'File';
        $action = $this->mustExist ? 'exists' : 'does not exist';

        return "{$type} '{$this->path}' {$action} requirement not met (expected: {$action})";
    }

    /**
     * Attempt to resolve the dependency.
     *
     * @return bool
     */
    public function resolve(): bool
    {
        if ($this->isSatisfied()) {
            return true;
        }

        $fullPath = base_path($this->path);
        
        try {
            if ($this->mustExist) {
                if ($this->isDirectory) {
                    return mkdir($fullPath, 0755, true);
                } else {
                    // Create parent directories if needed
                    $dir = dirname($fullPath);
                    if (!is_dir($dir)) {
                        mkdir($dir, 0755, true);
                    }
                    return touch($fullPath);
                }
            } else {
                // File should not exist - we can remove it
                if (is_dir($fullPath)) {
                    return rmdir($fullPath);
                } else {
                    return unlink($fullPath);
                }
            }
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get configuration options for this dependency.
     *
     * @return array
     */
    public function getConfigOptions(): array
    {
        return [
            'path' => [
                'type' => 'string',
                'description' => 'The file or directory path (relative to project root)',
                'required' => true,
            ],
            'must_exist' => [
                'type' => 'boolean',
                'description' => 'Whether the file/directory must exist',
                'default' => true,
            ],
            'is_directory' => [
                'type' => 'boolean',
                'description' => 'Whether the path is a directory',
                'default' => false,
            ]
        ];
    }
}