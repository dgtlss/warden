<?php

declare(strict_types=1);

return [
    'composer-cve' => 'replaced',
    'npm-cve' => 'replaced',
    'environment' => 'enforced',
    'gitignore-env' => 'replaced',
    'file-permissions' => 'advisory',
    'hardcoded-secrets' => 'enforced',
    'sql-injection' => 'enforced',
    'mass-assignment' => 'advisory',
    'xss' => 'enforced',
    'csrf' => 'enforced',
    'open-redirect' => 'enforced',
    'command-injection' => 'enforced',
    'insecure-deserialization' => 'enforced',
    'debug-functions' => 'advisory',
    'sensitive-exposure' => 'advisory',
    'ssrf' => 'enforced',
    'tls-verification' => 'enforced',
    'cors' => 'enforced',
    'package-freshness' => 'advisory',
    'supply-chain-tooling' => 'intentionally-omitted',
    'path-traversal' => 'enforced',
    'weak-cryptography' => 'enforced',
    'insecure-rng' => 'advisory',
    'session-security' => 'enforced',
    'eol-versions' => 'enforced',
    'suspicious-autoload' => 'replaced',
];
