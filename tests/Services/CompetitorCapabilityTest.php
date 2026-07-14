<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Tests\Services;

use Dgtlss\Warden\Tests\TestCase;

final class CompetitorCapabilityTest extends TestCase
{
    public function testEveryCompetitorCategoryHasAnExplicitDisposition(): void
    {
        $capabilities = require __DIR__ . '/../Fixtures/competitor-capabilities.php';

        self::assertCount(26, $capabilities);
        foreach ($capabilities as $category => $disposition) {
            self::assertIsString($category);
            self::assertContains($disposition, ['enforced', 'advisory', 'replaced', 'intentionally-omitted']);
        }
    }
}
