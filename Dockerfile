# syntax=docker/dockerfile:1

# Default is intentionally vulnerable: 8.3.35 is one release before the fix.
# Build with --build-arg PHP_VERSION=8.3.36 to get a patched image.
ARG PHP_VERSION=8.3.35
FROM php:${PHP_VERSION}-apache

LABEL org.opencontainers.image.title="php2shell-lab"
LABEL org.opencontainers.image.description="Intentionally vulnerable PHP image for demonstrating CVE-2026-109618 / CVE-2026-109619 (PHP2Shell). Lab use only."
LABEL org.opencontainers.image.source="https://github.com/bsalunke/php2shell-lab"

COPY php/99-php2shell-lab.ini /usr/local/etc/php/conf.d/
COPY src/ /var/www/html/

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD php -r '$s = @file_get_contents("http://127.0.0.1/status.php"); exit($s === false ? 1 : 0);'
