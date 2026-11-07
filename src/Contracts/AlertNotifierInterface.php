<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Contracts;

use JzGuilherme\LogSentinel\DTO\AiRootCauseDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;

/**
 * Contract for dispatching real-time DevOps incident notifications (Slack, Discord, Microsoft Teams).
 */
interface AlertNotifierInterface
{
    public function notify(SanitizedIncidentDTO $incident, AiRootCauseDTO $diagnosis, int $occurrences = 1): bool;
}
