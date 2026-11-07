<?php

declare(strict_types=1);

namespace JzGuilherme\LogSentinel\Tests\Unit;

use JzGuilherme\LogSentinel\Security\LgpdPiiScrubber;
use PHPUnit\Framework\TestCase;

final class LgpdPiiScrubberTest extends TestCase
{
    private LgpdPiiScrubber $scrubber;

    protected function setUp(): void
    {
        $this->scrubber = new LgpdPiiScrubber();
    }

    public function testMasksFormattedAndContextualCpfCnpjAndEmails(): void
    {
        $rawLog = 'Payment failed for customer CPF 123.456.789-01 (alt cpf: 98765432100), company CNPJ 12.345.678/0001-99 and email maria.souza@empresa.com.br';

        $result = $this->scrubber->scrubText($rawLog);

        self::assertStringNotContainsString('123.456.789-01', $result['sanitized']);
        self::assertStringNotContainsString('98765432100', $result['sanitized']);
        self::assertStringNotContainsString('12.345.678/0001-99', $result['sanitized']);
        self::assertStringNotContainsString('maria.souza@empresa.com.br', $result['sanitized']);

        self::assertStringContainsString('[REDACTED_CPF]', $result['sanitized']);
        self::assertStringContainsString('[REDACTED_CNPJ]', $result['sanitized']);
        self::assertStringContainsString('[REDACTED_EMAIL]', $result['sanitized']);
        self::assertGreaterThanOrEqual(4, $result['redacted_count']);
    }

    public function testMasksValidLuhnCreditCardsJwtAndSecretTokens(): void
    {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
        $rawLog = "Card 4532 0151 1283 0366 declined with token {$jwt} and password=MySecretPass123";

        $result = $this->scrubber->scrubText($rawLog);

        self::assertStringNotContainsString('4532 0151 1283 0366', $result['sanitized']);
        self::assertStringNotContainsString($jwt, $result['sanitized']);
        self::assertStringNotContainsString('MySecretPass123', $result['sanitized']);

        self::assertStringContainsString('[REDACTED_CARD]', $result['sanitized']);
        self::assertStringContainsString('[REDACTED_JWT]', $result['sanitized']);
        self::assertStringContainsString('[REDACTED_SECRET]', $result['sanitized']);
    }

    public function testRecursivelyScrubsSensitiveKeysInContextArray(): void
    {
        $context = [
            'order_id' => 9841,
            'customer' => [
                'name'        => 'Carlos',
                'cpf'         => '111.222.333-44',
                'card_number' => '4532015112830366',
                'notes'       => 'Contact at carlos@test.org',
            ],
            'password' => 'PlainTextSecret',
        ];

        $result = $this->scrubber->scrubContext($context);

        self::assertSame(9841, $result['sanitized']['order_id']);
        self::assertSame('[REDACTED_BY_KEY_POLICY]', $result['sanitized']['password']);
        self::assertIsArray($result['sanitized']['customer']);
        self::assertSame('[REDACTED_BY_KEY_POLICY]', $result['sanitized']['customer']['cpf']);
        self::assertSame('[REDACTED_BY_KEY_POLICY]', $result['sanitized']['customer']['card_number']);
        self::assertSame('Contact at [REDACTED_EMAIL]', $result['sanitized']['customer']['notes']);
        self::assertSame(4, $result['redacted_count']);
    }
}
