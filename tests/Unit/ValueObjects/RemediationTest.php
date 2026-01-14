<?php

namespace Dgtlss\Warden\Tests\Unit\ValueObjects;

use Dgtlss\Warden\Tests\TestCase;
use Dgtlss\Warden\ValueObjects\Remediation;

class RemediationTest extends TestCase
{
    public function testConstructorCreatesValidRemediation(): void
    {
        $remediation = new Remediation(
            description: 'Update the package to fix the vulnerability',
            commands: ['composer update vendor/package'],
            manualSteps: ['Review the changelog', 'Run tests'],
            links: ['https://example.com/advisory'],
            priority: 'high',
        );

        $this->assertEquals('Update the package to fix the vulnerability', $remediation->description);
        $this->assertEquals(['composer update vendor/package'], $remediation->commands);
        $this->assertEquals(['Review the changelog', 'Run tests'], $remediation->manualSteps);
        $this->assertEquals(['https://example.com/advisory'], $remediation->links);
        $this->assertEquals('high', $remediation->priority);
    }

    public function testConstructorWithDefaultValues(): void
    {
        $remediation = new Remediation(
            description: 'Fix the issue',
        );

        $this->assertEquals('Fix the issue', $remediation->description);
        $this->assertEquals([], $remediation->commands);
        $this->assertEquals([], $remediation->manualSteps);
        $this->assertEquals([], $remediation->links);
        $this->assertEquals('medium', $remediation->priority);
    }

    public function testFromArrayCreatesValidRemediation(): void
    {
        $data = [
            'description' => 'Update the package',
            'commands' => ['composer update vendor/package'],
            'manual_steps' => ['Review changes'],
            'links' => ['https://example.com'],
            'priority' => 'immediate',
        ];

        $remediation = Remediation::fromArray($data);

        $this->assertEquals('Update the package', $remediation->description);
        $this->assertEquals(['composer update vendor/package'], $remediation->commands);
        $this->assertEquals(['Review changes'], $remediation->manualSteps);
        $this->assertEquals(['https://example.com'], $remediation->links);
        $this->assertEquals('immediate', $remediation->priority);
    }

    public function testFromArrayWithEmptyData(): void
    {
        $remediation = Remediation::fromArray([]);

        $this->assertEquals('No remediation available', $remediation->description);
        $this->assertEquals([], $remediation->commands);
        $this->assertEquals([], $remediation->manualSteps);
        $this->assertEquals([], $remediation->links);
        $this->assertEquals('medium', $remediation->priority);
    }

    public function testFromArrayFiltersNonStringArrayValues(): void
    {
        $data = [
            'description' => 'Fix it',
            'commands' => ['valid command', 123, null, 'another command'],
            'manual_steps' => ['step 1', false, 'step 2'],
            'links' => ['https://example.com', [], 'https://example2.com'],
        ];

        $remediation = Remediation::fromArray($data);

        $this->assertEquals(['valid command', 'another command'], array_values($remediation->commands));
        $this->assertEquals(['step 1', 'step 2'], array_values($remediation->manualSteps));
        $this->assertEquals(['https://example.com', 'https://example2.com'], array_values($remediation->links));
    }

    public function testToArrayReturnsCorrectStructure(): void
    {
        $remediation = new Remediation(
            description: 'Update the package',
            commands: ['composer update vendor/package'],
            manualSteps: ['Review changes'],
            links: ['https://example.com'],
            priority: 'high',
        );

        $array = $remediation->toArray();

        $this->assertIsArray($array);
        $this->assertArrayHasKey('description', $array);
        $this->assertArrayHasKey('priority', $array);
        $this->assertArrayHasKey('commands', $array);
        $this->assertArrayHasKey('manual_steps', $array);
        $this->assertArrayHasKey('links', $array);

        $this->assertEquals('Update the package', $array['description']);
        $this->assertEquals('high', $array['priority']);
    }

    public function testToArrayOmitsEmptyArrays(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
            priority: 'low',
        );

        $array = $remediation->toArray();

        $this->assertArrayNotHasKey('commands', $array);
        $this->assertArrayNotHasKey('manual_steps', $array);
        $this->assertArrayNotHasKey('links', $array);
    }

    public function testHasCommandsReturnsTrueWhenCommandsExist(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
            commands: ['npm update'],
        );

        $this->assertTrue($remediation->hasCommands());
    }

    public function testHasCommandsReturnsFalseWhenEmpty(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
        );

        $this->assertFalse($remediation->hasCommands());
    }

    public function testHasManualStepsReturnsTrueWhenStepsExist(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
            manualSteps: ['Step 1'],
        );

        $this->assertTrue($remediation->hasManualSteps());
    }

    public function testHasManualStepsReturnsFalseWhenEmpty(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
        );

        $this->assertFalse($remediation->hasManualSteps());
    }

    public function testHasLinksReturnsTrueWhenLinksExist(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
            links: ['https://example.com'],
        );

        $this->assertTrue($remediation->hasLinks());
    }

    public function testHasLinksReturnsFalseWhenEmpty(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
        );

        $this->assertFalse($remediation->hasLinks());
    }

    public function testIsImmediateReturnsTrueForImmediatePriority(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
            priority: 'immediate',
        );

        $this->assertTrue($remediation->isImmediate());
    }

    public function testIsImmediateReturnsFalseForOtherPriorities(): void
    {
        $remediation = new Remediation(
            description: 'Fix it',
            priority: 'high',
        );

        $this->assertFalse($remediation->isImmediate());
    }

    public function testIsHighPriorityReturnsTrueForImmediateAndHigh(): void
    {
        $immediate = new Remediation(description: 'Fix it', priority: 'immediate');
        $high = new Remediation(description: 'Fix it', priority: 'high');

        $this->assertTrue($immediate->isHighPriority());
        $this->assertTrue($high->isHighPriority());
    }

    public function testIsHighPriorityReturnsFalseForMediumAndLow(): void
    {
        $medium = new Remediation(description: 'Fix it', priority: 'medium');
        $low = new Remediation(description: 'Fix it', priority: 'low');

        $this->assertFalse($medium->isHighPriority());
        $this->assertFalse($low->isHighPriority());
    }

    public function testSummaryReturnsFormattedString(): void
    {
        $remediation = new Remediation(
            description: 'Update vendor/package to fix the vulnerability',
            commands: ['composer update vendor/package'],
            priority: 'high',
        );

        $summary = $remediation->summary();

        $this->assertStringContainsString('HIGH', $summary);
        $this->assertStringContainsString('Update vendor/package', $summary);
        $this->assertStringContainsString('composer update vendor/package', $summary);
    }

    public function testSummaryWithoutCommands(): void
    {
        $remediation = new Remediation(
            description: 'Manual fix required',
            priority: 'medium',
        );

        $summary = $remediation->summary();

        $this->assertStringContainsString('MEDIUM', $summary);
        $this->assertStringContainsString('Manual fix required', $summary);
        $this->assertStringNotContainsString('Commands:', $summary);
    }

    public function testWithCreatesNewInstanceWithModifiedValues(): void
    {
        $original = new Remediation(
            description: 'Original description',
            commands: ['original command'],
            priority: 'low',
        );

        $modified = $original->with(
            description: 'Modified description',
            priority: 'high',
        );

        $this->assertEquals('Original description', $original->description);
        $this->assertEquals('low', $original->priority);

        $this->assertEquals('Modified description', $modified->description);
        $this->assertEquals('high', $modified->priority);
        $this->assertEquals(['original command'], $modified->commands);
    }

    public function testWithoutArgumentsReturnsNewInstanceWithSameValues(): void
    {
        $original = new Remediation(
            description: 'Test description',
            commands: ['test command'],
            priority: 'medium',
        );

        $copy = $original->with();

        $this->assertNotSame($original, $copy);

        $this->assertEquals($original->description, $copy->description);
        $this->assertEquals($original->commands, $copy->commands);
        $this->assertEquals($original->priority, $copy->priority);
    }
}
