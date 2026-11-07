<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Contracts;

use JzGuilherme\LogSentinel\DTO\AiRootCauseDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;
use JzGuilherme\LogSentinel\Exceptions\DiagnosticException;

/**
 * Contract for AI Root-Cause Diagnostic Providers operating exclusively on LGPD-sanitized incidents.
 */
interface AiDiagnosticProviderInterface
{
    /**
     * Analyzes a sanitized incident and returns a structured root-cause diagnosis and PHP fix.
     *
     * @throws DiagnosticException
     */
    public function analyzeIncident(SanitizedIncidentDTO $incident): AiRootCauseDTO;
}
