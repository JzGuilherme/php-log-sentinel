-- Migration: 001_create_sentinel_tables.sql
-- Engine: InnoDB (Supports atomic ON DUPLICATE KEY UPDATE and SELECT ... FOR UPDATE SKIP LOCKED)

SET NAMES utf8mb4;
SET TIME_ZONE = '+00:00';

CREATE TABLE IF NOT EXISTS `error_incidents` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `service_name` VARCHAR(100) NOT NULL,
    `environment` VARCHAR(32) NOT NULL DEFAULT 'production',
    `fingerprint` CHAR(64) NOT NULL COMMENT 'SHA-256 canonical hash of Exception + File + Line',
    `exception_class` VARCHAR(255) NOT NULL,
    `file_path` VARCHAR(512) NOT NULL,
    `line_number` INT UNSIGNED NOT NULL,
    `sanitized_message` TEXT NOT NULL COMMENT 'LGPD/GDPR scrubbed error message',
    `sanitized_stack_trace` LONGTEXT NOT NULL COMMENT 'LGPD/GDPR scrubbed stack trace',
    `sanitized_context` JSON NOT NULL COMMENT 'LGPD/GDPR scrubbed context payload',
    `redacted_pii_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Total PII tokens masked before storage',
    `occurrences` BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT 'Deduplicated count of identical error events',
    `status` ENUM('pending_triage', 'analyzing', 'diagnosed', 'failed', 'resolved') NOT NULL DEFAULT 'pending_triage',
    `first_seen_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_seen_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_incident_fingerprint` (`fingerprint`),
    INDEX `idx_triage_poll` (`status`, `last_seen_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `ai_diagnostics` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `incident_id` BIGINT UNSIGNED NOT NULL,
    `fingerprint` CHAR(64) NOT NULL,
    `severity` ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    `category` VARCHAR(64) NOT NULL COMMENT 'e.g. database_deadlock, null_pointer, third_party_timeout',
    `root_cause_summary` TEXT NOT NULL,
    `suggested_fix_code` TEXT NOT NULL,
    `prevention_checklist` JSON NOT NULL,
    `prompt_tokens` INT UNSIGNED NOT NULL DEFAULT 0,
    `completion_tokens` INT UNSIGNED NOT NULL DEFAULT 0,
    `alert_dispatched` TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_diagnostic_incident` (`incident_id`),
    INDEX `idx_severity_created` (`severity`, `created_at`),
    CONSTRAINT `fk_diagnostics_incident` FOREIGN KEY (`incident_id`) REFERENCES `error_incidents` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
