<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Services;

use JzGuilherme\LogSentinel\Contracts\AiDiagnosticProviderInterface;
use JzGuilherme\LogSentinel\Contracts\AlertNotifierInterface;
use JzGuilherme\LogSentinel\DTO\AiRootCauseDTO;
use JzGuilherme\LogSentinel\DTO\RawLogEventDTO;
use JzGuilherme\LogSentinel\DTO\SanitizedIncidentDTO;
use JzGuilherme\LogSentinel\Security\ErrorFingerprinter;
use PDO;

/**
 * Core Orchestrator that coordinates:
 * 1. In-memory LGPD PII scrubbing & SHA-256 fingerprinting
 * 2. Atomic deduplication in MySQL 8 (`ON DUPLICATE KEY UPDATE occurrences = occurrences + 1`)
 * 3. Concurrent background triage (`SELECT ... FOR UPDATE SKIP LOCKED`)
 * 4. AI root-cause diagnosis and DevOps webhook notification
 */
final class IncidentTriageService
{
    public function __construct(
        private readonly ErrorFingerprinter $fingerprinter,
        private readonly AiDiagnosticProviderInterface $aiProvider,
        private readonly AlertNotifierInterface $notifier,
        private readonly ?PDO $pdo = null
    ) {
    }

    /**
     * Scrubs PII in memory and records the deduplicated incident in MySQL.
     */
    public function ingestRawEvent(RawLogEventDTO $rawEvent): SanitizedIncidentDTO
    {
        $sanitized = $this->fingerprinter->sanitizeAndFingerprint($rawEvent);

        if ($this->pdo !== null) {
            $this->upsertIncident($sanitized);
        }

        return $sanitized;
    }

    /**
     * Performs an end-to-end synchronous triage (Scrub -> Fingerprint -> AI Root Cause -> Notify)
     * useful for unit testing or direct CLI diagnostics.
     *
     * @return array{incident: SanitizedIncidentDTO, diagnosis: AiRootCauseDTO}
     */
    public function triageDirectly(RawLogEventDTO $rawEvent): array
    {
        $incident = $this->ingestRawEvent($rawEvent);
        $diagnosis = $this->aiProvider->analyzeIncident($incident);
        $this->notifier->notify($incident, $diagnosis, 1);

        return [
            'incident'  => $incident,
            'diagnosis' => $diagnosis,
        ];
    }

    /**
     * Claims the next `pending_triage` incident using `FOR UPDATE SKIP LOCKED`,
     * calls Gemini 2.5 Flash for root-cause analysis, persists the diagnosis, and dispatches alerts.
     */
    public function processNextPendingIncident(): bool
    {
        if ($this->pdo === null) {
            return false;
        }

        $row = $this->claimNextIncident();
        if ($row === null) {
            return false;
        }

        $incidentId = (int) $row['id'];
        $occurrences = (int) $row['occurrences'];

        /** @var array<string, mixed> $context */
        $context = is_array(json_decode((string) $row['sanitized_context'], true))
            ? json_decode((string) $row['sanitized_context'], true)
            : [];

        $incident = new SanitizedIncidentDTO(
            serviceName: (string) $row['service_name'],
            environment: (string) $row['environment'],
            fingerprint: (string) $row['fingerprint'],
            exceptionClass: (string) $row['exception_class'],
            filePath: (string) $row['file_path'],
            lineNumber: (int) $row['line_number'],
            sanitizedMessage: (string) $row['sanitized_message'],
            sanitizedStackTrace: (string) $row['sanitized_stack_trace'],
            sanitizedContext: $context,
            redactedPiiCount: (int) $row['redacted_pii_count']
        );

        $diagnosis = $this->aiProvider->analyzeIncident($incident);
        $notified = $this->notifier->notify($incident, $diagnosis, $occurrences);

        $this->persistDiagnosis($incidentId, $incident->fingerprint, $diagnosis, $notified);

        return true;
    }

    private function upsertIncident(SanitizedIncidentDTO $incident): void
    {
        if ($this->pdo === null) {
            return;
        }

        $sql = <<<'SQL'
            INSERT INTO error_incidents (
                service_name,
                environment,
                fingerprint,
                exception_class,
                file_path,
                line_number,
                sanitized_message,
                sanitized_stack_trace,
                sanitized_context,
                redacted_pii_count,
                occurrences,
                status,
                first_seen_at,
                last_seen_at
            ) VALUES (
                :service_name,
                :environment,
                :fingerprint,
                :exception_class,
                :file_path,
                :line_number,
                :sanitized_message,
                :sanitized_stack_trace,
                :sanitized_context,
                :redacted_pii_count,
                1,
                'pending_triage',
                NOW(),
                NOW()
            )
            ON DUPLICATE KEY UPDATE
                occurrences = occurrences + 1,
                redacted_pii_count = redacted_pii_count + VALUES(redacted_pii_count),
                last_seen_at = NOW()
        SQL;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':service_name'          => $incident->serviceName,
            ':environment'           => $incident->environment,
            ':fingerprint'           => $incident->fingerprint,
            ':exception_class'       => $incident->exceptionClass,
            ':file_path'             => $incident->filePath,
            ':line_number'           => $incident->lineNumber,
            ':sanitized_message'     => $incident->sanitizedMessage,
            ':sanitized_stack_trace' => $incident->sanitizedStackTrace,
            ':sanitized_context'     => json_encode($incident->sanitizedContext, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            ':redacted_pii_count'    => $incident->redactedPiiCount,
        ]);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function claimNextIncident(): ?array
    {
        if ($this->pdo === null) {
            return null;
        }

        $this->pdo->beginTransaction();

        $sql = <<<'SQL'
            SELECT *
            FROM error_incidents
            WHERE status = 'pending_triage'
            ORDER BY last_seen_at DESC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        SQL;

        $stmt = $this->pdo->query($sql);
        /** @var array<string, mixed>|false $row */
        $row = $stmt !== false ? $stmt->fetch(PDO::FETCH_ASSOC) : false;

        if ($row === false || $row === []) {
            $this->pdo->commit();
            return null;
        }

        $update = $this->pdo->prepare("UPDATE error_incidents SET status = 'analyzing' WHERE id = :id");
        $update->execute([':id' => $row['id']]);
        $this->pdo->commit();

        return $row;
    }

    private function persistDiagnosis(
        int $incidentId,
        string $fingerprint,
        AiRootCauseDTO $diagnosis,
        bool $alertDispatched
    ): void {
        if ($this->pdo === null) {
            return;
        }

        $sql = <<<'SQL'
            INSERT INTO ai_diagnostics (
                incident_id,
                fingerprint,
                severity,
                category,
                root_cause_summary,
                suggested_fix_code,
                prevention_checklist,
                prompt_tokens,
                completion_tokens,
                alert_dispatched,
                created_at
            ) VALUES (
                :incident_id,
                :fingerprint,
                :severity,
                :category,
                :root_cause_summary,
                :suggested_fix_code,
                :prevention_checklist,
                :prompt_tokens,
                :completion_tokens,
                :alert_dispatched,
                NOW()
            )
        SQL;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':incident_id'          => $incidentId,
            ':fingerprint'          => $fingerprint,
            ':severity'             => $diagnosis->severity,
            ':category'             => $diagnosis->category,
            ':root_cause_summary'   => $diagnosis->rootCauseSummary,
            ':suggested_fix_code'   => $diagnosis->suggestedFixCode,
            ':prevention_checklist' => json_encode($diagnosis->preventionChecklist, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            ':prompt_tokens'        => $diagnosis->promptTokens,
            ':completion_tokens'    => $diagnosis->completionTokens,
            ':alert_dispatched'     => $alertDispatched ? 1 : 0,
        ]);

        $upd = $this->pdo->prepare("UPDATE error_incidents SET status = 'diagnosed' WHERE id = :id");
        $upd->execute([':id' => $incidentId]);
    }
}
