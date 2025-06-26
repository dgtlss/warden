<?php

namespace Dgtlss\Warden\Contracts;

interface NotificationChannel
{
    /**
     * Send audit findings through this channel.
     *
     * @param array $findings
     * @return void
     */
    public function send(array $findings): void;

    /**
     * Send abandoned packages notification through this channel.
     *
     * @param array $abandonedPackages
     * @return void
     */
    public function sendAbandonedPackages(array $abandonedPackages): void;

    /**
     * Check if this channel is configured and ready to use.
     *
     * @return bool
     */
    public function isConfigured(): bool;

    /**
     * Get the channel name.
     *
     * @return string
     */
    public function getName(): string;
} 