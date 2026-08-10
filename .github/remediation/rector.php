<?php

require_once __DIR__ . '/RegenerateSessionOnLoginRector.php';

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withRules([
        RegenerateSessionOnLoginRector::class,
    ]);
