# php2shell-lab

[![build](https://github.com/bsalunke/php2shell-lab/actions/workflows/build.yml/badge.svg)](https://github.com/bsalunke/php2shell-lab/actions/workflows/build.yml)

A deliberately vulnerable PHP container for demonstrating **PHP2Shell** — CVE-2026-109618 and
CVE-2026-109619 — the unauthenticated remote code execution and memory disclosure bugs in the PHP
engine itself.

> [!WARNING]
> This image is intentionally vulnerable and must never be exposed to the internet or run on a
> network you do not control. Run it locally, in an isolated lab network, and delete it when you are
> done. The repository contains **no exploit code**; the demonstration is that a trivial application
> on an unpatched PHP build is in scope.

## What this is

PHP2Shell is not an application bug. It lives in PHP's request lifecycle: a fatal error or
out-of-memory condition can abandon request cleanup, leaving stale pointers in worker-global state.
A later request handled by the same worker consumes that state before normal request initialization,
which can yield memory disclosure or code execution.

Wiz Research demonstrated the chain against stock `wordpress:latest`, `drupal:latest`, and
`joomla:latest` images, but noted that "even a simple Hello World application running on an affected
PHP version can be vulnerable." This lab is that Hello World: a small page, a file upload form, and
nothing else.

The image defaults to **PHP 8.3.35** (one release before the fix) on **Apache mod_php**, which is the
configuration where application-independent RCE was confirmed. Build with `PHP_VERSION=8.3.36` to get
a patched baseline and compare the two.

There is also a **Debian-packaged variant** ([`Dockerfile.distro`](Dockerfile.distro)) that installs
`php8.2` 8.2.32-1~deb12u1 from `bookworm/main` and pins it below the fixed 8.2.35. The official
`php:*` images compile PHP from source, so PHP never appears in the dpkg inventory and
package-based scanners cannot see it. The distro variant exists so scanners such as Qualys qscanner
can flag the CVEs against a real OS package.

## Vulnerabilities

| CVE | Advisory | Class | Impact |
| --- | --- | --- | --- |
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption | Unauthenticated RCE as the web worker |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state | Unauthenticated RCE; upload-progress UAF, fatal-error backtrace, OPcache type confusion |

Both are rated **CVSS v4.0 9.2 (Critical)**. Every PHP release from 5.4 onward is affected by at
least one variant, according to Wiz.

### Affected and fixed versions

| Branch | Affected | Fixed |
| --- | --- | --- |
| 8.5.x | < 8.5.12 | 8.5.12 |
| 8.4.x | < 8.4.27 | 8.4.27 |
| 8.3.x | < 8.3.36 | 8.3.36 |
| 8.2.x | < 8.2.35 | 8.2.35 |
| 8.1.x and older | no fix | unsupported — upgrade or take offline |

### Prerequisites

- `session.upload_progress.enabled=On` — the factory default, and explicitly set in this lab's
  [`php/99-php2shell-lab.ini`](php/99-php2shell-lab.ini).
- An endpoint that accepts `multipart/form-data`, even one that ignores the upload.
- A finite per-request `memory_limit` for the OOM-driven path.
- Apache mod_php for the confirmed application-independent RCE. FPM is considered susceptible, but
  no complete FPM exploit was demonstrated at disclosure.

## Quick start

With Compose:

```bash
docker compose up --build
```

Or with plain Docker:

```bash
docker build -t php2shell-lab:8.3.35 .
docker run --rm -p 127.0.0.1:8080:80 php2shell-lab:8.3.35
```

Then open <http://localhost:8080> or read the machine-readable status:

```bash
curl -s http://localhost:8080/status.php
```

```json
{
    "php_version": "8.3.35",
    "php_branch": "8.3",
    "fixed_in": "8.3.36",
    "vulnerable": true,
    "sapi": "apache2handler",
    "session_upload_progress": "On",
    "memory_limit": "128M",
    "post_max_size": "8M",
    "file_uploads": "On"
}
```

Run the assertion script:

```bash
EXPECT=vulnerable ./scripts/verify.sh
```

### Compare against a patched build

```bash
docker build --build-arg PHP_VERSION=8.3.36 -t php2shell-lab:8.3.36 .
docker run --rm -p 127.0.0.1:8081:80 php2shell-lab:8.3.36

BASE_URL=http://localhost:8081 EXPECT=patched ./scripts/verify.sh
```

The page banner and `status.php` flip from `vulnerable: true` to `vulnerable: false`. That is the
entire point: same application, same configuration, different PHP patch level.

### Debian-packaged build

```bash
docker build -f Dockerfile.distro -t php2shell-lab:8.2.32-distro .
docker run --rm -p 127.0.0.1:8082:80 php2shell-lab:8.2.32-distro

BASE_URL=http://localhost:8082 EXPECT=vulnerable ./scripts/verify.sh
```

Or via Compose: `docker compose --profile distro up --build` (port 8082).

```bash
docker exec <container> dpkg-query -W -f='${Package} ${Version}\n' 'php8.2*' 'libapache2-mod-php8.2'
# libapache2-mod-php8.2 8.2.32-1~deb12u1
# php8.2-cli 8.2.32-1~deb12u1
# php8.2-common 8.2.32-1~deb12u1
# php8.2-opcache 8.2.32-1~deb12u1
# php8.2-readline 8.2.32-1~deb12u1
```

## Scanning with Qualys qscanner

Credentials come from the environment; nothing is stored in the repository.

```bash
export QUALYS_CLIENT_ID=...
export QUALYS_CLIENT_SECRET=...

qscanner --pod US2 image php2shell-lab:8.2.32-distro
```

The distro variant is reported as vulnerable:

| QID | CVE | Installed | Fixed |
| --- | --- | --- | --- |
| 6297246 | CVE-2026-109618 | `php8.2` 8.2.32-1~deb12u1 | 8.2.35-1~deb12u1 |
| 6297238 | CVE-2026-109619 | `php8.2` 8.2.32-1~deb12u1 | 8.2.35-1~deb12u1 |

Both are reported against `php8.2-cli`, `php8.2-common`, `php8.2-opcache`, `php8.2-readline`, and
`libapache2-mod-php8.2`. Qualys scored them **65 (Medium)** at scan time, even though the CVSS v4
base score is 9.2.

Scanning the source-built `php2shell-lab:8.3.35` image instead returns **no vulnerabilities**: PHP is
not a dpkg package, so it never reaches the SBOM. That is expected, not a clean bill of health.

## Repository layout

```
.
├── Dockerfile                     # php:${PHP_VERSION}-apache, default 8.3.35
├── Dockerfile.distro              # Debian php8.2 8.2.32, visible to OS package scanners
├── docker-compose.yml             # localhost-only port binding
├── php/99-php2shell-lab.ini       # stock defaults, written out explicitly
├── src/
│   ├── index.php                  # status page + upload form
│   ├── upload.php                 # accepts multipart, deletes the temp file
│   ├── status.php                 # JSON status for scripting
│   └── lib.php                    # version check shared by the pages
├── scripts/verify.sh              # asserts vulnerable/patched
└── .github/workflows/build.yml    # builds both versions and verifies each
```

## Mitigation

**Upgrade PHP.** That is the only complete fix:

- 8.5.12, 8.4.27, 8.3.36, or 8.2.35, or later.

If you cannot upgrade immediately, the PHP advisories describe partial mitigations. Each closes one
path, not all of them:

| Measure | Effect | Caveat |
| --- | --- | --- |
| `session.upload_progress.enabled=0` | Closes the upload-progress consumer | Does not affect the fatal-error backtrace or OPcache arms; restart every worker |
| `fatal_error_backtraces=0` (8.5.x) | Removes the backtrace producer | 8.5.x only |
| Enforce `memory_limit=-1` administratively | Removes the predictable OOM trigger | Partial; removes PHP's own resource-exhaustion protection; never use `RLIMIT_AS`/`RLIMIT_DATA` |
| `pm.max_requests=1` (FPM) | Breaks the same-worker requirement | Availability and performance cost |
| Block `multipart/form-data` at the edge if unused | Removes the upload-progress surface | Application-dependent |
| Conservative `post_max_size`, input nesting/part/header caps | Reduces OOM and DoS reachability | Does not replace patching |
| WAF rules | Buys time | Not a fix; tune for false positives |

Restart all PHP workers after changing INI values. Settings such as `display_errors=0`,
`error_reporting=0`, or `@` suppression do **not** protect the early consumers described in the
advisories.

## Detection

CISA's alert recommends inventorying PHP deployments (including embedded copies), prioritizing
internet-facing systems, and watching for PHP worker processes that spawn shells or download tools.
Crash loops, repeated OOM events, and anomalous outbound traffic from web workers are also worth
alerting on.

## Scope and ethics

This repository exists for defender education, patch validation, and scanner testing. It ships no
weaponized exploit. Use it only on systems you own or are explicitly authorized to test. The
maintainers are not affiliated with the PHP project, Wiz, JFrog, Akamai, or CISA.

## References

- PHP advisory — RCE via OOM corruption: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- PHP advisory — RCE via stale global state: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- Wiz Research — PHP2Shell: <https://www.wiz.io/blog/php2shell-php-rce>
- JFrog Security Research — PHP2Shell: <https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/>
- Akamai — Understanding PHP2Shell: <https://www.akamai.com/blog/security-research/understanding-php2shell-everything-you-need-to-know>
- CISA alert: <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching>
- AWS Security Blog — WAF mitigations: <https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/>

## License

MIT — see [LICENSE](LICENSE).
