<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Enums\RuleDisposition;
use Dgtlss\Warden\ValueObjects\AuditError;
use Dgtlss\Warden\ValueObjects\AuditResult;
use Dgtlss\Warden\ValueObjects\Finding;

final class RulePolicy
{
    /** @var array<string, RuleDisposition> */
    private const DEFAULTS = [
        'source.secrets.provider-credential' => RuleDisposition::Enforced,
        'source.secrets.suspicious-literal' => RuleDisposition::Advisory,
        'source.php.sql-dynamic-raw' => RuleDisposition::Enforced,
        'source.php.command-tainted-input' => RuleDisposition::Enforced,
        'source.php.unsafe-deserialization' => RuleDisposition::Enforced,
        'source.php.ssrf-tainted-url' => RuleDisposition::Enforced,
        'source.php.path-traversal' => RuleDisposition::Enforced,
        'source.php.open-redirect' => RuleDisposition::Enforced,
        'source.php.xss-tainted-output' => RuleDisposition::Enforced,
        'source.php.tls-verification-disabled' => RuleDisposition::Enforced,
        'source.php.weak-cipher' => RuleDisposition::Enforced,
        'source.laravel.csrf-disabled' => RuleDisposition::Enforced,
        'source.blade.unescaped-output' => RuleDisposition::Advisory,
        'source.blade.form-missing-csrf' => RuleDisposition::Advisory,
        'source.laravel.mass-assignment-disabled' => RuleDisposition::Advisory,
        'source.php.debug-call' => RuleDisposition::Advisory,
        'source.php.sensitive-log' => RuleDisposition::Advisory,
        'source.php.weak-hash-context' => RuleDisposition::Advisory,
        'source.php.insecure-rng-context' => RuleDisposition::Advisory,
        'laravel.cors.wildcard-credentials' => RuleDisposition::Enforced,
        'laravel.cors.wildcard-origin' => RuleDisposition::Advisory,
        'laravel.debug-tool.telescope-enabled' => RuleDisposition::Enforced,
        'laravel.debug-tool.debugbar-enabled' => RuleDisposition::Enforced,
        'laravel.debug-tool.clockwork-enabled' => RuleDisposition::Enforced,
        'deployment.env.permissions' => RuleDisposition::Advisory,
        'deployment.path.world-writable' => RuleDisposition::Advisory,
        'platform.php.eol' => RuleDisposition::Enforced,
        'platform.php.security-only' => RuleDisposition::Advisory,
        'platform.laravel.eol' => RuleDisposition::Enforced,
        'platform.laravel.security-only' => RuleDisposition::Advisory,
        'supply-chain.composer.recent-package' => RuleDisposition::Advisory,
        'supply-chain.composer.recent-executable-package' => RuleDisposition::Enforced,
        'supply-chain.composer.release-time-missing' => RuleDisposition::Advisory,
    ];

    /** @return list<AuditError> */
    public function errors(): array
    {
        $overrides = config('warden.rule_overrides', []);
        if (!is_array($overrides)) {
            return [new AuditError('configuration', 'invalid_rule_overrides', 'warden.rule_overrides must be an array.')];
        }

        $errors = [];
        foreach ($overrides as $id => $value) {
            if (!is_string($id) || !isset(self::DEFAULTS[$id])) {
                $errors[] = new AuditError('configuration', 'unknown_rule', sprintf('Unknown rule override "%s".', (string) $id));
                continue;
            }

            if (!is_string($value) || RuleDisposition::tryFrom($value) === null) {
                $errors[] = new AuditError('configuration', 'invalid_rule_disposition', sprintf('Rule "%s" must be enforced, advisory, or off.', $id));
            }
        }

        return $errors;
    }

    public function disposition(string $id): ?RuleDisposition
    {
        $default = self::DEFAULTS[$id] ?? null;
        if ($default === null) {
            return null;
        }

        $overrides = config('warden.rule_overrides', []);
        $override = is_array($overrides) ? ($overrides[$id] ?? null) : null;

        return is_string($override) ? (RuleDisposition::tryFrom($override) ?? $default) : $default;
    }

    public function enabled(string $id): bool
    {
        return $this->disposition($id) !== RuleDisposition::Off;
    }

    /**
     * @param list<AuditResult> $results
     * @return list<AuditResult>
     */
    public function apply(array $results): array
    {
        $updated = [];
        foreach ($results as $result) {
            $findings = [];
            foreach ($result->findings as $finding) {
                $disposition = $this->disposition($finding->id);
                if ($disposition === RuleDisposition::Off) {
                    continue;
                }

                $findings[] = $disposition instanceof \Dgtlss\Warden\Enums\RuleDisposition
                    ? $finding->withBlocking($disposition === RuleDisposition::Enforced)
                    : $finding;
            }

            $updated[] = $result->withFindings($findings);
        }

        return $updated;
    }

    /** @return list<string> */
    public function ruleIds(): array
    {
        return array_keys(self::DEFAULTS);
    }
}
