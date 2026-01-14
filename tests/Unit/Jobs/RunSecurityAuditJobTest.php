<?php

namespace Dgtlss\Warden\Tests\Unit\Jobs;

use Dgtlss\Warden\Jobs\RunSecurityAuditJob;
use Dgtlss\Warden\Services\AuditCacheService;
use Dgtlss\Warden\Services\ParallelAuditExecutor;
use Dgtlss\Warden\Services\RemediationService;
use Dgtlss\Warden\Tests\TestCase;
use Illuminate\Support\Facades\Queue;

class RunSecurityAuditJobTest extends TestCase
{
    public function testJobCanBeInstantiated(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertInstanceOf(RunSecurityAuditJob::class, $job);
    }

    public function testJobHasDefaultAuditTypes(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertContains('composer', $job->auditTypes);
        $this->assertContains('env', $job->auditTypes);
        $this->assertContains('storage', $job->auditTypes);
        $this->assertContains('debug', $job->auditTypes);
    }

    public function testJobAcceptsCustomAuditTypes(): void
    {
        $job = new RunSecurityAuditJob(auditTypes: ['composer', 'npm']);

        $this->assertEquals(['composer', 'npm'], $job->auditTypes);
    }

    public function testJobAcceptsSeverityFilter(): void
    {
        $job = new RunSecurityAuditJob(severity: 'high');

        $this->assertEquals('high', $job->severity);
    }

    public function testJobAcceptsNotifyFlag(): void
    {
        $job = new RunSecurityAuditJob(notify: false);

        $this->assertFalse($job->notify);
    }

    public function testJobAcceptsForceRefreshFlag(): void
    {
        $job = new RunSecurityAuditJob(forceRefresh: true);

        $this->assertTrue($job->forceRefresh);
    }

    public function testJobAcceptsRemediationFlag(): void
    {
        $job = new RunSecurityAuditJob(includeRemediation: false);

        $this->assertFalse($job->includeRemediation);
    }

    public function testJobHasCorrectTries(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertEquals(3, $job->tries);
    }

    public function testJobHasCorrectTimeout(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertEquals(300, $job->timeout);
    }

    public function testJobCanBeQueued(): void
    {
        Queue::fake();

        $job = new RunSecurityAuditJob(
            auditTypes: ['composer'],
            severity: 'medium',
            notify: true,
        );

        dispatch($job);

        Queue::assertPushed(RunSecurityAuditJob::class, function ($pushedJob) {
            return $pushedJob->auditTypes === ['composer']
                && $pushedJob->severity === 'medium'
                && $pushedJob->notify === true;
        });
    }

    public function testJobCanBeQueuedOnSpecificConnection(): void
    {
        Queue::fake();

        $job = new RunSecurityAuditJob();
        $job->onConnection('redis');
        $job->onQueue('audits');

        dispatch($job);

        Queue::assertPushed(RunSecurityAuditJob::class);
    }

    public function testJobDefaultNotifyIsTrue(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertTrue($job->notify);
    }

    public function testJobDefaultForceRefreshIsFalse(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertFalse($job->forceRefresh);
    }

    public function testJobDefaultIncludeRemediationIsTrue(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertTrue($job->includeRemediation);
    }

    public function testJobDefaultSeverityIsNull(): void
    {
        $job = new RunSecurityAuditJob();

        $this->assertNull($job->severity);
    }
}
