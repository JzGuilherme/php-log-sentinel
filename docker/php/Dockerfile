FROM php:8.3-cli-alpine

LABEL maintainer="José Guilherme <https://github.com/JzGuilherme>"
LABEL description="PHP 8.3 CLI container for PHP Log Sentinel with pdo_mysql, pcntl, curl, mbstring and supervisor"

RUN apk add --no-cache \
    bash \
    curl \
    curl-dev \
    git \
    icu-dev \
    oniguruma-dev \
    supervisor \
    unzip \
    zip

RUN docker-php-ext-install -j$(nproc) \
    curl \
    intl \
    mbstring \
    opcache \
    pcntl \
    pdo \
    pdo_mysql

RUN { \
    echo "memory_limit=256M"; \
    echo "max_execution_time=0"; \
    echo "opcache.enable_cli=1"; \
    } > /usr/local/etc/php/conf.d/sentinel-cli.ini

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

RUN mkdir -p /var/www/html/logs /var/log/supervisor \
    && chown -R www-data:www-data /var/www/html

CMD ["php", "-a"]
