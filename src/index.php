<?php

declare(strict_types=1);

require __DIR__ . '/lib.php';

$status = php2shell_status();
$vulnerable = $status['vulnerable'];

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PHP2Shell Lab</title>
    <style>
        :root { color-scheme: dark; }
        body {
            margin: 0;
            padding: 2rem 1rem;
            background: #0f1115;
            color: #e6e6e6;
            font: 15px/1.6 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        }
        main { max-width: 860px; margin: 0 auto; }
        h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
        .sub { color: #8b949e; margin: 0 0 1.5rem; }
        .banner {
            padding: 1rem 1.25rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border: 1px solid;
        }
        .vulnerable { background: #2b1113; border-color: #7d2a2f; color: #ffb3b8; }
        .patched { background: #0f2417; border-color: #2c6b42; color: #9be9b8; }
        .banner strong { display: block; font-size: 1.05rem; margin-bottom: .25rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0 2rem; }
        th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; font-weight: 500; width: 45%; }
        code { color: #79c0ff; }
        section { border-top: 1px solid #21262d; padding-top: 1.5rem; margin-top: 1.5rem; }
        h2 { font-size: 1.05rem; margin: 0 0 .75rem; }
        form { display: flex; gap: .75rem; align-items: center; flex-wrap: wrap; }
        input[type=file] { color: #c9d1d9; }
        button {
            background: #238636;
            color: #fff;
            border: 0;
            border-radius: 6px;
            padding: .5rem 1rem;
            font: inherit;
            cursor: pointer;
        }
        a { color: #58a6ff; }
    </style>
</head>
<body>
<main>
    <h1>PHP2Shell Lab</h1>
    <p class="sub">A deliberately boring PHP app on an intentionally vulnerable PHP build.</p>

    <div class="banner <?= $vulnerable ? 'vulnerable' : 'patched' ?>">
        <strong><?= $vulnerable ? 'Vulnerable to PHP2Shell' : 'Patched against PHP2Shell' ?></strong>
        PHP <?= e($status['php_version']) ?> (<?= e($status['sapi']) ?>).
        <?php if ($vulnerable): ?>
            Fixed in <?= e($status['fixed_in'] ?? 'a supported PHP branch') ?>.
        <?php else: ?>
            CVE-2026-109618 and CVE-2026-109619 are fixed in this release.
        <?php endif; ?>
    </div>

    <table>
        <tr><th>PHP version</th><td><code><?= e($status['php_version']) ?></code></td></tr>
        <tr><th>Server API</th><td><code><?= e($status['sapi']) ?></code></td></tr>
        <tr><th>session.upload_progress.enabled</th><td><code><?= e((string) $status['session_upload_progress']) ?></code></td></tr>
        <tr><th>memory_limit</th><td><code><?= e((string) $status['memory_limit']) ?></code></td></tr>
        <tr><th>post_max_size</th><td><code><?= e((string) $status['post_max_size']) ?></code></td></tr>
        <tr><th>file_uploads</th><td><code><?= e((string) $status['file_uploads']) ?></code></td></tr>
    </table>

    <section>
        <h2>Upload a file</h2>
        <p>
            This endpoint accepts a multipart upload and does nothing interesting with it.
            PHP parses the request body before this page's code runs, so the application
            logic below is irrelevant to the vulnerability.
        </p>
        <form action="upload.php" method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
    </section>

    <section>
        <h2>Why this page is the demo</h2>
        <p>
            CVE-2026-109618 and CVE-2026-109619 are memory-safety bugs in the PHP engine,
            not in application code. Any PHP deployment that accepts multipart requests is
            in scope, even one as small as this. Patching PHP is the only complete fix.
        </p>
        <p>
            Machine-readable status: <a href="status.php">status.php</a>
        </p>
    </section>
</main>
</body>
</html>
