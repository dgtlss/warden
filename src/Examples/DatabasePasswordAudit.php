<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Examples;

use Dgtlss\Warden\Contracts\CustomAudit;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\AuditContext;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;

final class DatabasePasswordAudit implements CustomAudit
{
    public function getName(): string
    {
        return 'database-password';
    }

    public function getDescription(): string
    {
        return 'Checks the effective database configuration for common placeholder passwords.';
    }

    public function shouldRun(AuditContext $auditContext): bool
    {
        return $auditContext->profile === 'production' && is_string(config('database.default'));
    }

    public function run(AuditContext $auditContext): AuditResult
    {
        $connection = config('database.default');
        $password = is_string($connection) ? config(sprintf('database.connections.%s.password', $connection)) : null;
        if (!is_string($password) || !in_array(strtolower($password), ['password', '123456', 'admin'], true)) {
            return AuditResult::complete($this->getName());
        }

        return AuditResult::complete($this->getName(), [new Finding(
            id: 'custom.database-password.placeholder',
            source: $this->getName(),
            title: 'Database uses a common placeholder password',
            severity: Severity::Critical,
            description: 'The effective database password matches a commonly guessed placeholder.',
            remediation: 'Rotate it to a unique secret stored by the deployment platform.',
            package: 'application',
            path: 'config/database.php',
        )]);
    }
}
