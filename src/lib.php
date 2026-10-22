<?php

declare(strict_types=1);

const PHP2SHELL_FIXED_VERSIONS = [
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
];

function php2shell_branch(): string
{
    return implode('.', array_slice(explode('.', PHP_VERSION), 0, 2));
}

function php2shell_is_vulnerable(): bool
{
    $fixed = PHP2SHELL_FIXED_VERSIONS[php2shell_branch()] ?? null;

    // Unsupported branches (8.1 and older) have no fix at all.
    return $fixed === null || version_compare(PHP_VERSION, $fixed, '<');
}

function php2shell_ini_bool(string $key): string
{
    return filter_var(ini_get($key), FILTER_VALIDATE_BOOLEAN) ? 'On' : 'Off';
}

function php2shell_status(): array
{
    $branch = php2shell_branch();

    return [
        'php_version' => PHP_VERSION,
        'php_branch' => $branch,
        'fixed_in' => PHP2SHELL_FIXED_VERSIONS[$branch] ?? null,
        'vulnerable' => php2shell_is_vulnerable(),
        'sapi' => PHP_SAPI,
        'session_upload_progress' => php2shell_ini_bool('session.upload_progress.enabled'),
        'memory_limit' => ini_get('memory_limit'),
        'post_max_size' => ini_get('post_max_size'),
        'file_uploads' => php2shell_ini_bool('file_uploads'),
    ];
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
