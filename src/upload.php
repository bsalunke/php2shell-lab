<?php

declare(strict_types=1);

require __DIR__ . '/lib.php';

$file = $_FILES['file'] ?? null;
$uploaded = is_array($file) && ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK;
$name = $uploaded ? basename((string) $file['name']) : null;
$size = $uploaded ? (int) $file['size'] : 0;

// Never store attacker-supplied files in a lab image.
if ($uploaded && is_uploaded_file($file['tmp_name'])) {
    unlink($file['tmp_name']);
}

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PHP2Shell Lab &middot; Upload</title>
    <style>
        :root { color-scheme: dark; }
        body {
            margin: 0;
            padding: 2rem 1rem;
            background: #0f1115;
            color: #e6e6e6;
            font: 15px/1.6 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        }
        main { max-width: 640px; margin: 0 auto; }
        h1 { font-size: 1.25rem; }
        .ok { color: #9be9b8; }
        .err { color: #ffb3b8; }
        a { color: #58a6ff; }
    </style>
</head>
<body>
<main>
    <h1>Upload result</h1>
    <?php if ($uploaded): ?>
        <p class="ok">Received <code><?= e((string) $name) ?></code> (<?= $size ?> bytes). Temp file deleted.</p>
    <?php else: ?>
        <p class="err">No file received. Upload error code: <?= e((string) ($file['error'] ?? UPLOAD_ERR_NO_FILE)) ?>.</p>
    <?php endif; ?>
    <p><a href="index.php">Back</a></p>
</main>
</body>
</html>
