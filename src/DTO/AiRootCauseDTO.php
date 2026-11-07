<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\DTO;

use JsonSerializable;

/**
 * Immutable DTO holding the structured AI root-cause diagnosis, suggested PHP patch,
 * prevention checklist, and LLM token telemetry.
 */
final readonly class AiRootCauseDTO implements JsonSerializable
{
    /**
     * @param string $severity One of: 'critical', 'high', 'medium', 'low'
     * @param string $category Short error classification slug
     * @param string $rootCauseSummary Clear technical explanation of the failure cause
     * @param string $suggestedFixCode Concrete PHP code patch or defensive check
     * @param array<int, string> $preventionChecklist Actionable engineering items
     * @param int $promptTokens Input token count
     * @param int $completionTokens Output token count
     */
    public function __construct(
        public string $severity,
        public string $category,
        public string $rootCauseSummary,
        public string $suggestedFixCode,
        public array $preventionChecklist,
        public int $promptTokens = 0,
        public int $completionTokens = 0
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'severity'             => $this->severity,
            'category'             => $this->category,
            'root_cause_summary'   => $this->rootCauseSummary,
            'suggested_fix_code'   => $this->suggestedFixCode,
            'prevention_checklist' => $this->preventionChecklist,
            'prompt_tokens'        => $this->promptTokens,
            'completion_tokens'    => $this->completionTokens,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
