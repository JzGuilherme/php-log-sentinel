<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Security;

use JzGuilherme\LogSentinel\Contracts\PiiScrubberInterface;

/**
 * LGPD & GDPR Compliance Engine that detects and masks Personally Identifiable Information (PII)
 * and authentication secrets before logs are stored or sent to external AI providers.
 *
 * Masks:
 * - Brazilian CPF (formatted and unformatted contextual)
 * - Brazilian CNPJ
 * - Credit Card numbers (13 to 19 digits passing Luhn check or standard card patterns)
 * - JWT Bearer tokens & API keys (Google AIza, Stripe sk_live, Bearer headers)
 * - Email addresses
 * - Inline password/secret assignments
 */
final class LgpdPiiScrubber implements PiiScrubberInterface
{
    private const SENSITIVE_KEYS = [
        'password',
        'senha',
        'pass',
        'pwd',
        'secret',
        'client_secret',
        'api_key',
        'apikey',
        'access_token',
        'refresh_token',
        'authorization',
        'jwt',
        'card_number',
        'numero_cartao',
        'cvv',
        'cvc',
        'cpf',
        'cnpj',
        'documento',
    ];

    /**
     * @inheritDoc
     */
    public function scrubText(string $rawText): array
    {
        if ($rawText === '') {
            return ['sanitized' => '', 'redacted_count' => 0];
        }

        $totalRedacted = 0;
        $text = $rawText;

        // 1. Mask JWT tokens (eyJ... . eyJ... . signature)
        $text = (string) preg_replace(
            '/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/',
            '[REDACTED_JWT]',
            $text,
            -1,
            $count
        );
        $totalRedacted += $count;

        // 2. Mask Authorization Bearer / Basic tokens and known API key prefixes (AIza..., sk_live_..., ghp_...)
        $text = (string) preg_replace(
            '/(?:Bearer\s+[A-Za-z0-9._~+\/-]{12,}|\b(?:AIza[0-9A-Za-z_-]{35}|sk_(?:live|test)_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{20,})\b)/i',
            '[REDACTED_SECRET_TOKEN]',
            $text,
            -1,
            $count
        );
        $totalRedacted += $count;

        // 3. Mask inline password/secret key-value pairs in URLs, JSON or query strings
        $text = (string) preg_replace(
            '/((?:password|senha|secret|api_key|token|cvv)["\']?\s*(?:=|:)\s*["\']?)([^"\'\s&,;}]+)/i',
            '$1[REDACTED_SECRET]',
            $text,
            -1,
            $count
        );
        $totalRedacted += $count;

        // 4. Mask Brazilian CNPJ (XX.XXX.XXX/XXXX-XX)
        $text = (string) preg_replace(
            '/\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/',
            '[REDACTED_CNPJ]',
            $text,
            -1,
            $count
        );
        $totalRedacted += $count;

        // 5. Mask Credit Card numbers (13 to 19 digits with spaces or dashes) BEFORE CPF so 16-digit cards aren't partially matched
        $text = (string) preg_replace_callback(
            '/\b(?:\d[ -]*?){13,19}\b/',
            function (array $matches) use (&$totalRedacted): string {
                $digitsOnly = (string) preg_replace('/\D/', '', $matches[0]);
                if (strlen($digitsOnly) >= 13 && strlen($digitsOnly) <= 19 && $this->passesLuhnCheck($digitsOnly)) {
                    $totalRedacted++;
                    return '[REDACTED_CARD]';
                }
                return $matches[0];
            },
            $text
        );

        // 6. Mask Brazilian CPF (formatted XXX.XXX.XXX-XX or contextual cpf: XXXXXXXXXXX)
        $text = (string) preg_replace(
            '/(?:\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|(?<=cpf[\s:= "\'])\d{11}\b)/i',
            '[REDACTED_CPF]',
            $text,
            -1,
            $count
        );
        $totalRedacted += $count;

        // 7. Mask Email addresses
        $text = (string) preg_replace(
            '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/',
            '[REDACTED_EMAIL]',
            $text,
            -1,
            $count
        );
        $totalRedacted += $count;

        return [
            'sanitized'      => $text,
            'redacted_count' => $totalRedacted,
        ];
    }

    /**
     * @inheritDoc
     */
    public function scrubContext(array $context): array
    {
        $sanitized = [];
        $totalRedacted = 0;

        foreach ($context as $key => $value) {
            $normalizedKey = strtolower(trim((string) $key));

            if ($this->isSensitiveKey($normalizedKey)) {
                $sanitized[$key] = '[REDACTED_BY_KEY_POLICY]';
                $totalRedacted++;
                continue;
            }

            if (is_array($value)) {
                /** @var array<string, mixed> $nestedArray */
                $nestedArray = $value;
                $nestedResult = $this->scrubContext($nestedArray);
                $sanitized[$key] = $nestedResult['sanitized'];
                $totalRedacted += $nestedResult['redacted_count'];
            } elseif (is_string($value)) {
                $stringResult = $this->scrubText($value);
                $sanitized[$key] = $stringResult['sanitized'];
                $totalRedacted += $stringResult['redacted_count'];
            } else {
                $sanitized[$key] = $value;
            }
        }

        return [
            'sanitized'      => $sanitized,
            'redacted_count' => $totalRedacted,
        ];
    }

    private function isSensitiveKey(string $normalizedKey): bool
    {
        foreach (self::SENSITIVE_KEYS as $sensitive) {
            if ($normalizedKey === $sensitive || str_contains($normalizedKey, $sensitive)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validates a numeric string using the Luhn checksum algorithm for credit card detection.
     */
    public function passesLuhnCheck(string $number): bool
    {
        $sum = 0;
        $numDigits = strlen($number);
        $parity = $numDigits % 2;

        for ($i = 0; $i < $numDigits; $i++) {
            $digit = (int) $number[$i];
            if ($i % 2 === $parity) {
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }
            $sum += $digit;
        }

        return $sum > 0 && ($sum % 10 === 0);
    }
}
