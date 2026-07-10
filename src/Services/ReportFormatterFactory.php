<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Contracts\ReportFormatter;
use Dgtlss\Warden\Reporters\ConsoleReporter;
use Dgtlss\Warden\Reporters\GitHubReporter;
use Dgtlss\Warden\Reporters\GitLabReporter;
use Dgtlss\Warden\Reporters\JsonReporter;
use Dgtlss\Warden\Reporters\JunitReporter;
use Dgtlss\Warden\Reporters\SarifReporter;
use InvalidArgumentException;

final class ReportFormatterFactory
{
    public function make(string $format): ReportFormatter
    {
        return match ($format) {
            'console' => new ConsoleReporter(),
            'json' => new JsonReporter(),
            'github' => new GitHubReporter(),
            'gitlab' => new GitLabReporter(),
            'sarif' => new SarifReporter(),
            'junit' => new JunitReporter(),
            default => throw new InvalidArgumentException(sprintf('Unsupported report format "%s".', $format)),
        };
    }
}
