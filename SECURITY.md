# Security policy

## This repository is intentionally vulnerable

`php2shell-lab` builds an image with a PHP release affected by CVE-2026-109618 and CVE-2026-109619
(PHP2Shell). Do not deploy it to production, expose it to the internet, or run it on a shared
network. It is a local training and patch-validation artifact.

## Reporting

- **A problem with the lab itself** (for example, the container escaping its intended scope, or an
  unintended vulnerability in the sample application): open a GitHub issue or contact the maintainer
  privately.
- **A vulnerability in PHP**: report it to the PHP project via
  <https://github.com/php/php-src/security/policy>. Do not open a public issue for an unpatched PHP
  vulnerability.

## Supported versions

There are no supported versions. The vulnerable build is deliberately pinned to an unpatched PHP
release.
