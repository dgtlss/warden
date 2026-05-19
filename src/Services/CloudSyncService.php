<?php

namespace Dgtlss\Warden\Services;

use Illuminate\Support\Facades\Http;

class CloudSyncService
{
    public function isEnabled(): bool
    {
        return (bool) config('warden.cloud.enabled', false);
    }

    public function isConfigured(): bool
    {
        return $this->isEnabled()
            && is_string(config('warden.cloud.base_url'))
            && config('warden.cloud.base_url') !== ''
            && is_string(config('warden.cloud.token'))
            && config('warden.cloud.token') !== '';
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function sync(array $payload): bool
    {
        if (!$this->isConfigured()) {
            return false;
        }

        $response = Http::withToken((string) config('warden.cloud.token'))
            ->acceptJson()
            ->post(rtrim((string) config('warden.cloud.base_url'), '/') . '/api/v1/runs', $payload);

        if ($response->successful()) {
            return true;
        }

        if ((bool) config('warden.cloud.fail_closed', false)) {
            throw new \RuntimeException('Warden Cloud sync failed: ' . $response->body());
        }

        return false;
    }
}
