<?php

declare(strict_types=1);

use Dotenv\Dotenv;

/**
 * Injectable PDO Connection Factory for PHP Log Sentinel.
 *
 * @return Closure(array<string, mixed>=): PDO
 */
return static function (array $overrides = []): PDO {
    $rootDir = dirname(__DIR__);

    if (class_exists(Dotenv::class) && file_exists($rootDir . '/.env')) {
        Dotenv::createImmutable($rootDir)->safeLoad();
    }

    $host = (string) ($overrides['host'] ?? $_ENV['DB_HOST'] ?? getenv('DB_HOST') ?: '127.0.0.1');
    $port = (int) ($overrides['port'] ?? $_ENV['DB_PORT'] ?? getenv('DB_PORT') ?: 3306);
    $database = (string) ($overrides['database'] ?? $_ENV['DB_DATABASE'] ?? getenv('DB_DATABASE') ?: 'log_sentinel');
    $username = (string) ($overrides['username'] ?? $_ENV['DB_USERNAME'] ?? getenv('DB_USERNAME') ?: 'sentinel_user');
    $password = (string) ($overrides['password'] ?? $_ENV['DB_PASSWORD'] ?? getenv('DB_PASSWORD') ?: '');

    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $database);

    try {
        return new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_STRINGIFY_FETCHES  => false,
        ]);
    } catch (PDOException $e) {
        throw new RuntimeException(
            sprintf('Database connection failed for host "%s:%d" and schema "%s".', $host, $port, $database),
            (int) $e->getCode()
        );
    }
};
