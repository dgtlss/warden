<?php

namespace Dgtlss\Warden\Tests\Unit\Services;

use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Tests\TestCase;
use Mockery;

class ParallelAuditExecutorTest extends TestCase
{
    public function testAddAuditStoresService(): void
    {
        $executor = new ParallelAuditExecutor();

        $auditService = Mockery::mock();
        $auditService->shouldReceive('getName')->andReturn('test-audit');

        $executor->addAudit($auditService);

        // Verify by executing (should not be empty)
        $reflection = new \ReflectionClass($executor);
        $property = $reflection->getProperty('processes');
        $property->setAccessible(true);
        $processes = $property->getValue($executor);

        $this->assertNotEmpty($processes);
        $this->assertArrayHasKey('test-audit', $processes);
    }

    public function testExecuteWithNoAudits(): void
    {
        $executor = new ParallelAuditExecutor();

        $results = $executor->execute(false);

        $this->assertIsArray($results);
        $this->assertEmpty($results);
    }

    public function testExecuteWithSuccessfulAudit(): void
    {
        $executor = new ParallelAuditExecutor();

        $auditService = Mockery::mock();
        $auditService->shouldReceive('getName')->andReturn('test-audit');
        $auditService->shouldReceive('run')->andReturn(true);
        $auditService->shouldReceive('getFindings')->andReturn([]);

        $executor->addAudit($auditService);

        $results = $executor->execute(false);

        $this->assertIsArray($results);
        $this->assertArrayHasKey('test-audit', $results);
        $this->assertTrue($results['test-audit']['success']);
        $this->assertEmpty($results['test-audit']['findings']);
        $this->assertSame($auditService, $results['test-audit']['service']);
    }

    public function testExecuteWithFailedAudit(): void
    {
        $executor = new ParallelAuditExecutor();

        $auditService = Mockery::mock();
        $auditService->shouldReceive('getName')->andReturn('failing-audit');
        $auditService->shouldReceive('run')->andReturn(false);
        $auditService->shouldReceive('getFindings')->andReturn([
            [
                'package' => 'test',
                'title' => 'Test failure',
                'severity' => 'high',
            ]
        ]);

        $executor->addAudit($auditService);

        $results = $executor->execute(false);

        $this->assertIsArray($results);
        $this->assertArrayHasKey('failing-audit', $results);
        $this->assertFalse($results['failing-audit']['success']);
        $this->assertNotEmpty($results['failing-audit']['findings']);
        $this->assertCount(1, $results['failing-audit']['findings']);
    }

    public function testExecuteWithMultipleAudits(): void
    {
        $executor = new ParallelAuditExecutor();

        $audit1 = Mockery::mock();
        $audit1->shouldReceive('getName')->andReturn('audit-1');
        $audit1->shouldReceive('run')->andReturn(true);
        $audit1->shouldReceive('getFindings')->andReturn([]);

        $audit2 = Mockery::mock();
        $audit2->shouldReceive('getName')->andReturn('audit-2');
        $audit2->shouldReceive('run')->andReturn(true);
        $audit2->shouldReceive('getFindings')->andReturn([
            ['package' => 'pkg', 'title' => 'Issue', 'severity' => 'medium']
        ]);

        $executor->addAudit($audit1);
        $executor->addAudit($audit2);

        $results = $executor->execute(false);

        $this->assertCount(2, $results);
        $this->assertArrayHasKey('audit-1', $results);
        $this->assertArrayHasKey('audit-2', $results);
        $this->assertTrue($results['audit-1']['success']);
        $this->assertTrue($results['audit-2']['success']);
        $this->assertEmpty($results['audit-1']['findings']);
        $this->assertCount(1, $results['audit-2']['findings']);
    }

    public function testGetAllFindingsReturnsEmptyWhenNoResults(): void
    {
        $executor = new ParallelAuditExecutor();

        $findings = $executor->getAllFindings();

        $this->assertInstanceOf(\Illuminate\Support\Collection::class, $findings);
        $this->assertTrue($findings->isEmpty());
    }

    public function testHasFailuresReturnsFalseWhenNoFailures(): void
    {
        $executor = new ParallelAuditExecutor();

        $auditService = Mockery::mock();
        $auditService->shouldReceive('getName')->andReturn('success-audit');
        $auditService->shouldReceive('run')->andReturn(true);
        $auditService->shouldReceive('getFindings')->andReturn([]);

        $executor->addAudit($auditService);
        $executor->execute(false);

        // Store results for testing
        $reflection = new \ReflectionClass($executor);
        $property = $reflection->getProperty('results');
        $property->setAccessible(true);
        $property->setValue($executor, [
            'success-audit' => [
                'success' => true,
                'findings' => [],
                'service' => $auditService
            ]
        ]);

        $this->assertFalse($executor->hasFailures());
    }

    public function testHasFailuresReturnsTrueWhenFailuresExist(): void
    {
        $executor = new ParallelAuditExecutor();

        // Set results manually for testing
        $reflection = new \ReflectionClass($executor);
        $property = $reflection->getProperty('results');
        $property->setAccessible(true);
        $property->setValue($executor, [
            'failed-audit' => [
                'success' => false,
                'findings' => [['error' => 'test']],
                'service' => Mockery::mock()
            ]
        ]);

        $this->assertTrue($executor->hasFailures());
    }

    public function testGetFailedAuditsReturnsFailedNames(): void
    {
        $executor = new ParallelAuditExecutor();

        // Set results manually
        $reflection = new \ReflectionClass($executor);
        $property = $reflection->getProperty('results');
        $property->setAccessible(true);
        $property->setValue($executor, [
            'success-audit' => ['success' => true, 'findings' => [], 'service' => Mockery::mock()],
            'failed-audit-1' => ['success' => false, 'findings' => [], 'service' => Mockery::mock()],
            'failed-audit-2' => ['success' => false, 'findings' => [], 'service' => Mockery::mock()],
        ]);

        $failed = $executor->getFailedAudits();

        $this->assertInstanceOf(\Illuminate\Support\Collection::class, $failed);
        $this->assertCount(2, $failed);
        $this->assertTrue($failed->contains('failed-audit-1'));
        $this->assertTrue($failed->contains('failed-audit-2'));
        $this->assertFalse($failed->contains('success-audit'));
    }
}
