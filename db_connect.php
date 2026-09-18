<?php
/**
 * ================================================================================
 * Intelligent Login Attempt Monitoring and Intrusion Detection System (IDS)
 * PHP MySQL Database Connector & Web Auditor Script
 * ================================================================================
 */

// MySQL Database Credentials Configuration
$host     = 'localhost';
$port     = '3306';
$db_name  = 'cyber_ids_db';
$user     = 'root';
$password = '';
$charset  = 'utf8mb4';

// PDO Connection DSN
$dsn = "mysql:host=$host;port=$port;dbname=$db_name;charset=$charset";

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    // 1. Establish PDO Connection to MySQL Server
    $pdo = new PDO($dsn, $user, $password, $options);
    $status_msg = "Successfully Connected to MySQL Database [cyber_ids_db]";
    $status_class = "success";

    // 2. Fetch Users Data from MySQL Database
    $stmt_users = $pdo->query("SELECT id, username, email, role, is_verified, is_locked, security_score, created_at FROM users ORDER BY created_at DESC");
    $users = $stmt_users->fetchAll();

    // 3. Fetch Recent Monitored Login Attempts
    $stmt_logins = $pdo->query("SELECT * FROM login_attempts ORDER BY timestamp DESC LIMIT 15");
    $login_attempts = $stmt_logins->fetchAll();

} catch (\PDOException $e) {
    $status_msg = "Database Connection Error: " . $e->getMessage();
    $status_class = "danger";
    $users = [];
    $login_attempts = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber IDS - PHP Database Viewer</title>
    <!-- Bootstrap 5 CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- FontAwesome 6 CDN -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #070b14; color: #e2e8f0; font-family: system-ui, sans-serif; }
        .cyber-card { background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(0, 242, 254, 0.2); border-radius: 12px; }
        .text-cyan { color: #00f2fe; }
        .mono { font-family: monospace; }
    </style>
</head>
<body class="py-5">
    <div class="container">
        
        <!-- Database Header -->
        <div class="cyber-card p-4 mb-4">
            <h2 class="text-white"><i class="fa-brands fa-php text-primary me-2"></i>PHP MySQL Database Viewer</h2>
            <p class="text-secondary small mb-3">Intelligent Login Attempt Monitoring & Intrusion Detection System (IDS)</p>
            
            <div class="alert alert-<?= $status_class ?> mb-0">
                <i class="fa-solid fa-database me-2"></i> <?= htmlspecialchars($status_msg) ?>
            </div>
        </div>

        <!-- 1. Registered Users Table (PHP Engine) -->
        <div class="cyber-card p-4 mb-4">
            <h4 class="text-cyan mb-3"><i class="fa-solid fa-users me-2"></i>Registered Users Table (`users`)</h4>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr class="text-cyan">
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Security Score</th>
                            <th>Created At</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($users)): ?>
                            <?php foreach ($users as $u): ?>
                                <tr>
                                    <td class="mono">#<?= htmlspecialchars($u['id']) ?></td>
                                    <td class="fw-bold"><?= htmlspecialchars($u['username']) ?></td>
                                    <td class="mono text-cyan"><?= htmlspecialchars($u['email']) ?></td>
                                    <td><span class="badge bg-secondary"><?= htmlspecialchars($u['role']) ?></span></td>
                                    <td>
                                        <?php if ($u['is_locked']): ?>
                                            <span class="badge bg-danger">LOCKED</span>
                                        <?php else: ?>
                                            <span class="badge bg-success">ACTIVE</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><span class="badge bg-dark border border-info"><?= number_format($u['security_score'], 1) ?></span></td>
                                    <td class="mono small"><?= htmlspecialchars($u['created_at']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr><td colspan="7" class="text-center text-muted">No records found or MySQL not connected.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- 2. Monitored Login Attempts Table (PHP Engine) -->
        <div class="cyber-card p-4">
            <h4 class="text-cyan mb-3"><i class="fa-solid fa-list-check me-2"></i>Audit Logs Table (`login_attempts`)</h4>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr class="text-cyan">
                            <th>Timestamp</th>
                            <th>Attempt Username</th>
                            <th>IP Address</th>
                            <th>Browser / OS</th>
                            <th>Status</th>
                            <th>Risk Level</th>
                            <th>Threat Tags</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($login_attempts)): ?>
                            <?php foreach ($login_attempts as $log): ?>
                                <tr>
                                    <td class="mono small"><?= htmlspecialchars(substr($log['timestamp'], 0, 19)) ?></td>
                                    <td class="fw-bold"><?= htmlspecialchars($log['attempt_username']) ?></td>
                                    <td class="mono text-cyan"><?= htmlspecialchars($log['ip_address']) ?></td>
                                    <td class="small"><?= htmlspecialchars($log['browser']) ?> (<?= htmlspecialchars($log['operating_system']) ?>)</td>
                                    <td>
                                        <span class="badge bg-<?= $log['login_status'] === 'SUCCESS' ? 'success' : ($log['login_status'] === 'FAILED' ? 'warning' : 'danger') ?>">
                                            <?= htmlspecialchars($log['login_status']) ?>
                                        </span>
                                    </td>
                                    <td><span class="badge bg-dark border border-cyan"><?= htmlspecialchars($log['risk_score']) ?> (<?= htmlspecialchars($log['risk_level']) ?>)</span></td>
                                    <td class="mono text-danger small"><?= htmlspecialchars($log['threat_types'] ?: 'None') ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr><td colspan="7" class="text-center text-muted">No login audit logs found.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</body>
</html>
