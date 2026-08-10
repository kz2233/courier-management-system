<?php

/**
 * Shared session bootstrap for the remediation workflow.
 *
 * Secure cookies are enabled whenever Apache reports HTTPS (including a
 * trusted local reverse-proxy header) or when the fixed deployment explicitly
 * sets SESSION_COOKIE_SECURE=1.
 */
$forwardedProto = strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
$isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
    || $forwardedProto === 'https'
    || getenv('SESSION_COOKIE_SECURE') === '1';

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}
