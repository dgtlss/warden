<?php

namespace Dgtlss\Warden\Tests\Unit\Enums;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\Tests\TestCase;

class SeverityTest extends TestCase
{
    public function testAllCasesExist(): void
    {
        $cases = Severity::cases();

        $this->assertCount(7, $cases);
        $this->assertContains(Severity::CRITICAL, $cases);
        $this->assertContains(Severity::HIGH, $cases);
        $this->assertContains(Severity::MEDIUM, $cases);
        $this->assertContains(Severity::MODERATE, $cases);
        $this->assertContains(Severity::LOW, $cases);
        $this->assertContains(Severity::ERROR, $cases);
        $this->assertContains(Severity::UNKNOWN, $cases);
    }

    public function testLabelReturnsCorrectValues(): void
    {
        $this->assertEquals('Critical', Severity::CRITICAL->label());
        $this->assertEquals('High', Severity::HIGH->label());
        $this->assertEquals('Medium', Severity::MEDIUM->label());
        $this->assertEquals('Moderate', Severity::MODERATE->label());
        $this->assertEquals('Low', Severity::LOW->label());
        $this->assertEquals('Error', Severity::ERROR->label());
        $this->assertEquals('Unknown', Severity::UNKNOWN->label());
    }

    public function testPriorityReturnsCorrectValues(): void
    {
        $this->assertEquals(5, Severity::CRITICAL->priority());
        $this->assertEquals(4, Severity::HIGH->priority());
        $this->assertEquals(3, Severity::MEDIUM->priority());
        $this->assertEquals(3, Severity::MODERATE->priority());
        $this->assertEquals(2, Severity::LOW->priority());
        $this->assertEquals(1, Severity::ERROR->priority());
        $this->assertEquals(0, Severity::UNKNOWN->priority());
    }

    public function testColorReturnsHexValues(): void
    {
        $this->assertEquals('#FF0000', Severity::CRITICAL->color());
        $this->assertEquals('#FF6B6B', Severity::HIGH->color());
        $this->assertEquals('#FFA500', Severity::MEDIUM->color());
        $this->assertEquals('#FFA500', Severity::MODERATE->color());
        $this->assertEquals('#FFD700', Severity::LOW->color());
        $this->assertEquals('#DC143C', Severity::ERROR->color());
        $this->assertEquals('#808080', Severity::UNKNOWN->color());
    }

    public function testToGitHubLevelMapsCorrectly(): void
    {
        $this->assertEquals('error', Severity::CRITICAL->toGitHubLevel());
        $this->assertEquals('error', Severity::HIGH->toGitHubLevel());
        $this->assertEquals('warning', Severity::MEDIUM->toGitHubLevel());
        $this->assertEquals('warning', Severity::MODERATE->toGitHubLevel());
        $this->assertEquals('notice', Severity::LOW->toGitHubLevel());
        $this->assertEquals('notice', Severity::ERROR->toGitHubLevel());
        $this->assertEquals('notice', Severity::UNKNOWN->toGitHubLevel());
    }

    public function testFromStringCreatesCorrectEnum(): void
    {
        $this->assertSame(Severity::CRITICAL, Severity::fromString('critical'));
        $this->assertSame(Severity::HIGH, Severity::fromString('high'));
        $this->assertSame(Severity::MEDIUM, Severity::fromString('medium'));
        $this->assertSame(Severity::MODERATE, Severity::fromString('moderate'));
        $this->assertSame(Severity::LOW, Severity::fromString('low'));
        $this->assertSame(Severity::ERROR, Severity::fromString('error'));
    }

    public function testFromStringIsCaseInsensitive(): void
    {
        $this->assertSame(Severity::CRITICAL, Severity::fromString('CRITICAL'));
        $this->assertSame(Severity::HIGH, Severity::fromString('High'));
        $this->assertSame(Severity::MEDIUM, Severity::fromString('MeDiUm'));
    }

    public function testFromStringHandlesWhitespace(): void
    {
        $this->assertSame(Severity::CRITICAL, Severity::fromString('  critical  '));
        $this->assertSame(Severity::HIGH, Severity::fromString("\thigh\n"));
    }

    public function testFromStringReturnsUnknownForInvalidValue(): void
    {
        $this->assertSame(Severity::UNKNOWN, Severity::fromString('invalid'));
        $this->assertSame(Severity::UNKNOWN, Severity::fromString(''));
        $this->assertSame(Severity::UNKNOWN, Severity::fromString('xyz'));
    }

    public function testSortedByPriorityReturnsAllCases(): void
    {
        $sorted = Severity::sortedByPriority();

        $this->assertCount(7, $sorted);
        $this->assertContainsOnlyInstancesOf(Severity::class, $sorted);
    }

    public function testSortedByPriorityOrdersCorrectly(): void
    {
        $sorted = Severity::sortedByPriority();

        // First should be CRITICAL (highest priority)
        $this->assertSame(Severity::CRITICAL, $sorted[0]);

        // Last should be UNKNOWN (lowest priority)
        $this->assertSame(Severity::UNKNOWN, $sorted[count($sorted) - 1]);

        // Verify priorities are descending
        for ($i = 0; $i < count($sorted) - 1; $i++) {
            $this->assertGreaterThanOrEqual(
                $sorted[$i + 1]->priority(),
                $sorted[$i]->priority(),
                'Priorities should be in descending order'
            );
        }
    }

    public function testEnumValuesMatchStrings(): void
    {
        $this->assertEquals('critical', Severity::CRITICAL->value);
        $this->assertEquals('high', Severity::HIGH->value);
        $this->assertEquals('medium', Severity::MEDIUM->value);
        $this->assertEquals('moderate', Severity::MODERATE->value);
        $this->assertEquals('low', Severity::LOW->value);
        $this->assertEquals('error', Severity::ERROR->value);
        $this->assertEquals('unknown', Severity::UNKNOWN->value);
    }
}
