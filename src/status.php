<?php

declare(strict_types=1);

require __DIR__ . '/lib.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

echo json_encode(php2shell_status(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
