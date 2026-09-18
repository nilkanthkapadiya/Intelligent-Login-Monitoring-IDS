-- ================================================================================
-- Intelligent Login Attempt Monitoring and Intrusion Detection System (IDS)
-- Production MySQL 8.x Database Export for phpMyAdmin / MySQL Workbench
-- Engine: InnoDB | Character Set: utf8mb4 | Collation: utf8mb4_unicode_ci
-- ================================================================================

SET FOREIGN_KEY_CHECKS = 0;

CREATE DATABASE IF NOT EXISTS `cyber_ids_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cyber_ids_db`;

DROP TABLE IF EXISTS `active_sessions`;
DROP TABLE IF EXISTS `recovery_methods`;
DROP TABLE IF EXISTS `trusted_devices`;
DROP TABLE IF EXISTS `security_alerts`;
DROP TABLE IF EXISTS `login_attempts`;
DROP TABLE IF EXISTS `password_resets`;
DROP TABLE IF EXISTS `verification_otps`;
DROP TABLE IF EXISTS `system_logs`;
DROP TABLE IF EXISTS `users`;

SET FOREIGN_KEY_CHECKS = 1;

-- --------------------------------------------------------
-- Table structure for table `users`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(80) NOT NULL,
    `email` VARCHAR(120) NOT NULL,
    `mobile` VARCHAR(20) DEFAULT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(20) NOT NULL DEFAULT 'User',
    `is_verified` TINYINT(1) NOT NULL DEFAULT 1,
    `is_locked` TINYINT(1) NOT NULL DEFAULT 0,
    `locked_until` DATETIME DEFAULT NULL,
    `failed_attempts_count` INT NOT NULL DEFAULT 0,
    `security_score` FLOAT NOT NULL DEFAULT 100.0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_users_username` (`username`),
    UNIQUE KEY `uk_users_email` (`email`),
    KEY `idx_users_email` (`email`),
    KEY `idx_users_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `login_attempts`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `login_attempts` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `user_id` INT DEFAULT NULL,
    `attempt_username` VARCHAR(120) NOT NULL,
    `attempt_email` VARCHAR(120) DEFAULT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NOT NULL,
    `browser` VARCHAR(50) DEFAULT 'Unknown',
    `operating_system` VARCHAR(50) DEFAULT 'Unknown',
    `device_type` VARCHAR(50) DEFAULT 'Unknown',
    `country` VARCHAR(60) DEFAULT 'Unknown',
    `city` VARCHAR(60) DEFAULT 'Unknown',
    `login_status` VARCHAR(20) NOT NULL,
    `failure_reason` VARCHAR(255) DEFAULT NULL,
    `session_id` VARCHAR(128) DEFAULT NULL,
    `risk_score` FLOAT NOT NULL DEFAULT 0.0,
    `risk_level` VARCHAR(20) NOT NULL DEFAULT 'Safe',
    `threat_types` TEXT DEFAULT NULL,
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_login_ip` (`ip_address`),
    KEY `idx_login_status` (`login_status`),
    KEY `idx_login_timestamp` (`timestamp`),
    KEY `idx_login_risk` (`risk_level`),
    KEY `idx_login_user_id` (`user_id`),
    CONSTRAINT `fk_login_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `security_alerts`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security_alerts` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `user_id` INT DEFAULT NULL,
    `alert_title` VARCHAR(150) NOT NULL,
    `alert_type` VARCHAR(50) NOT NULL,
    `severity` VARCHAR(20) NOT NULL,
    `description` TEXT NOT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `is_resolved` TINYINT(1) NOT NULL DEFAULT 0,
    `resolved_at` DATETIME DEFAULT NULL,
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_alerts_user_id` (`user_id`),
    KEY `idx_alerts_severity` (`severity`),
    KEY `idx_alerts_resolved` (`is_resolved`),
    CONSTRAINT `fk_alerts_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `trusted_devices`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `trusted_devices` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `user_id` INT NOT NULL,
    `device_fingerprint` VARCHAR(128) NOT NULL,
    `device_name` VARCHAR(100) NOT NULL,
    `browser` VARCHAR(50) DEFAULT NULL,
    `os` VARCHAR(50) DEFAULT NULL,
    `last_ip` VARCHAR(45) DEFAULT NULL,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `first_seen` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_seen` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_trusted_dev_user` (`user_id`),
    KEY `idx_trusted_dev_fp` (`device_fingerprint`),
    CONSTRAINT `fk_trusted_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `system_logs`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `system_logs` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `log_level` VARCHAR(20) NOT NULL,
    `module` VARCHAR(50) NOT NULL,
    `event_action` VARCHAR(100) NOT NULL,
    `message` TEXT NOT NULL,
    `details` TEXT DEFAULT NULL,
    `performed_by` VARCHAR(80) DEFAULT 'SYSTEM',
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_system_logs_level` (`log_level`),
    KEY `idx_system_logs_module` (`module`),
    KEY `idx_system_logs_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Dumping Seed Data for `users`
-- --------------------------------------------------------
INSERT INTO `users` (`id`, `username`, `email`, `mobile`, `password_hash`, `role`, `is_verified`, `is_locked`, `security_score`) VALUES
(1, 'admin', 'admin@security.soc', '+1555019920', '$2b$12$e6yD9tM/lFkUfN/6C0kFce/zN41M6P1hK9S/9Jp2b7eW8g1h2i3j4', 'Admin', 1, 0, 98.5),
(2, 'john_doe', 'john@example.com', '+1555014433', '$2b$12$e6yD9tM/lFkUfN/6C0kFce/zN41M6P1hK9S/9Jp2b7eW8g1h2i3j4', 'User', 1, 0, 92.0),
(3, 'alice_smith', 'alice@example.com', '+1555017788', '$2b$12$e6yD9tM/lFkUfN/6C0kFce/zN41M6P1hK9S/9Jp2b7eW8g1h2i3j4', 'User', 1, 0, 88.0),
(4, 'bob_target', 'bob@example.com', '+1555012211', '$2b$12$e6yD9tM/lFkUfN/6C0kFce/zN41M6P1hK9S/9Jp2b7eW8g1h2i3j4', 'User', 1, 1, 35.0);

-- --------------------------------------------------------
-- Dumping Seed Data for `login_attempts`
-- --------------------------------------------------------
INSERT INTO `login_attempts` (`user_id`, `attempt_username`, `attempt_email`, `ip_address`, `user_agent`, `browser`, `operating_system`, `device_type`, `country`, `login_status`, `risk_score`, `risk_level`, `threat_types`) VALUES
(1, 'admin', 'admin@security.soc', '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0)', 'Chrome', 'Windows 10', 'Desktop', 'United States', 'SUCCESS', 5.0, 'Safe', NULL),
(2, 'john_doe', 'john@example.com', '192.168.1.45', 'Mozilla/5.0 (Macintosh; Intel Mac OS X)', 'Safari', 'macOS', 'Desktop', 'United States', 'SUCCESS', 12.0, 'Safe', NULL),
(4, 'bob_target', 'bob@example.com', '185.220.101.5', 'Python-urllib/3.10', 'Python Script', 'Linux', 'Bot', 'Russia', 'FAILED', 78.0, 'High', 'TOR_NODE,PASSWORD_SPRAY'),
(4, 'bob_target', 'bob@example.com', '185.220.101.5', 'Python-urllib/3.10', 'Python Script', 'Linux', 'Bot', 'Russia', 'FAILED', 84.0, 'High', 'BRUTE_FORCE,TOR_NODE'),
(4, 'bob_target', 'bob@example.com', '185.220.101.5', 'Python-urllib/3.10', 'Python Script', 'Linux', 'Bot', 'Russia', 'FAILED', 92.0, 'Critical', 'BRUTE_FORCE,ACCOUNT_LOCKED'),
(4, 'bob_target', 'bob@example.com', '185.220.101.5', 'Python-urllib/3.10', 'Python Script', 'Linux', 'Bot', 'Russia', 'BLOCKED', 98.0, 'Critical', 'BLOCKED_ATTEMPT');

-- --------------------------------------------------------
-- Dumping Seed Data for `security_alerts`
-- --------------------------------------------------------
INSERT INTO `security_alerts` (`user_id`, `alert_title`, `alert_type`, `severity`, `description`, `ip_address`, `is_resolved`) VALUES
(4, 'Automated Brute Force Threshold Exceeded', 'BRUTE_FORCE', 'Critical', 'Account bob_target experienced 5 consecutive failed logins within 5 minutes from IP 185.220.101.5.', '185.220.101.5', 0),
(3, 'Impossible Travel Velocity Detected', 'IMPOSSIBLE_TRAVEL', 'High', 'User alice_smith logged in from Japan 10 minutes after a login session in the US.', '103.21.244.0', 0);
