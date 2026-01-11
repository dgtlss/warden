<?php

namespace Dgtlss\Warden\Contracts;

interface NotificationChannel
{
    /**
     * Send audit findings through this channel.
     *
     * @param array<int, array<string, mixed>> $findings
     */
    public function send(array $findings): void;

    /**
     * Send abandoned packages notification through this channel.
     *
     * @param array<int, array<string, mixed>> $abandonedPackages
     */
    public function sendAbandonedPackages(array $abandonedPackages): void;

    /**
     * Check if this channel is configured and ready to use.
     */
    public function isConfigured(): bool;

    /**
     * Get the channel name.
     */
    public function getName(): string;
} 