<?php
/**
 * xsukax E2EE Local Mailing System - Backend API
 * Version: 1.0.0
 * Author: xsukax
 * 
 * Zero-Knowledge End-to-End Encrypted Messaging System
 * - AES-256-GCM encryption (client-side only)
 * - Server never has access to encryption keys or decrypted content
 * - JWT-based authentication
 * - SQLite database for persistence
 * - Works on any domain with nginx or Apache
 * - No server configuration changes required
 * 
 * Security Features:
 * - PBKDF2 key derivation (100,000 iterations)
 * - Password hashing with bcrypt (cost 12)
 * - SQL injection prevention with prepared statements
 * - Input validation and sanitization
 * - CORS support for cross-origin requests
 * - Secure session management with JWT tokens
 */

// Error reporting configuration
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');

// CORS Headers - Must be set before any output
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Access-Control-Max-Age: 3600');
header('Content-Type: application/json; charset=utf-8');

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Configuration - Automatically adapts to any domain
define('DB_FILE', __DIR__ . '/xsukax_mail.db');
define('JWT_SECRET', 'change-me' . hash('sha256', __DIR__ . $_SERVER['HTTP_HOST']));
define('DOMAIN', $_SERVER['HTTP_HOST'] ?? 'localhost');
define('VERSION', '1.0.0');

/**
 * Initialize SQLite database with proper schema and indexes
 */
function initDatabase() {
    try {
        $db = new PDO('sqlite:' . DB_FILE);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_TIMEOUT, 10);
        
        // Enable WAL mode for better concurrency and performance
        $db->exec("PRAGMA journal_mode=WAL");
        $db->exec("PRAGMA synchronous=NORMAL");
        
        // Create users table
        $db->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(username, domain)
            )
        ");
        
        // Create messages table
        $db->exec("
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                subject TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                encrypted_attachments TEXT,
                is_deleted INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_user) REFERENCES users(email),
                FOREIGN KEY (to_user) REFERENCES users(email)
            )
        ");
        
        // Create indexes for query performance
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_to_user ON messages(to_user)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_from_user ON messages(from_user)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_deleted ON messages(is_deleted)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC)");
        
        return $db;
    } catch (PDOException $e) {
        error_log("Database initialization failed: " . $e->getMessage());
        http_response_code(500);
        echo json_encode([
            'success' => false, 
            'message' => 'Database initialization failed',
            'error' => 'Please check error.log for details'
        ]);
        exit();
    }
}

/**
 * Get database connection (singleton pattern)
 */
function getDB() {
    static $db = null;
    if ($db === null) {
        $db = initDatabase();
    }
    return $db;
}

/**
 * Generate JWT token for authentication
 */
function generateJWT($userId, $email) {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64_encode(json_encode([
        'user_id' => $userId,
        'email' => $email,
        'domain' => DOMAIN,
        'iat' => time(),
        'exp' => time() + (7 * 24 * 60 * 60) // 7 days expiration
    ]));
    
    $signature = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $signature = base64_encode($signature);
    
    return "$header.$payload.$signature";
}

/**
 * Verify and decode JWT token
 */
function verifyJWT($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }
    
    list($header, $payload, $signature) = $parts;
    
    // Verify signature
    $validSignature = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    
    if ($signature !== $validSignature) {
        return false;
    }
    
    // Decode payload
    $payloadData = json_decode(base64_decode($payload), true);
    
    // Check expiration
    if (!$payloadData || $payloadData['exp'] < time()) {
        return false;
    }
    
    return $payloadData;
}

/**
 * Get authenticated user from request headers
 */
function getAuthUser() {
    $headers = getallheaders();
    if (!$headers) {
        $headers = [];
    }
    
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    
    if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        return null;
    }
    
    return verifyJWT($matches[1]);
}

/**
 * Validate email address format
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Sanitize user input to prevent XSS
 */
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Send JSON response and exit
 */
function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit();
}

/**
 * Send error response
 */
function errorResponse($message, $statusCode = 400) {
    jsonResponse(['success' => false, 'message' => $message], $statusCode);
}

/**
 * Send success response
 */
function successResponse($data = []) {
    jsonResponse(array_merge(['success' => true], $data));
}

/**
 * Parse request path - works on both Apache and nginx
 */
function getRequestPath() {
    $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
    $scriptName = $_SERVER['SCRIPT_NAME'] ?? '/index.php';
    
    // Remove query string
    $path = parse_url($requestUri, PHP_URL_PATH);
    
    // Get the directory of the script
    $scriptDir = dirname($scriptName);
    
    // Remove script directory from path
    if ($scriptDir !== '/' && strpos($path, $scriptDir) === 0) {
        $path = substr($path, strlen($scriptDir));
    }
    
    // Remove /index.php from path if present
    $path = preg_replace('#/index\.php#', '', $path);
    
    // Normalize path
    $path = '/' . trim($path, '/');
    
    return $path;
}

// Get request method and path
$requestMethod = $_SERVER['REQUEST_METHOD'];
$path = getRequestPath();

// Log request for debugging
error_log("xsukax E2EE Mail: $requestMethod $path");

// ============================================================================
// API ROUTES
// ============================================================================

try {
    // GET /info or / - Server information
    if (($path === '/info' || $path === '/' || $path === '') && $requestMethod === 'GET') {
        successResponse([
            'domain' => DOMAIN,
            'version' => VERSION,
            'system' => 'xsukax E2EE Local Mailing System',
            'encryption' => 'AES-256-GCM (client-side)',
            'server' => php_sapi_name(),
            'timestamp' => date('c'),
            'message' => 'End-to-End Encrypted Mail Server - Ready'
        ]);
    }
    
    // POST /register - Create new user account
    elseif ($path === '/register' && $requestMethod === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            errorResponse('Invalid JSON input');
        }
        
        $username = sanitizeInput($input['username'] ?? '');
        $password = $input['password'] ?? '';
        
        // Validation
        if (empty($username) || empty($password)) {
            errorResponse('Username and password are required');
        }
        
        if (!preg_match('/^[a-zA-Z0-9_-]{3,30}$/', $username)) {
            errorResponse('Username must be 3-30 characters (alphanumeric, underscore, hyphen only)');
        }
        
        if (strlen($password) < 6) {
            errorResponse('Password must be at least 6 characters');
        }
        
        // Create user
        $email = $username . '@' . DOMAIN;
        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        try {
            $db = getDB();
            $stmt = $db->prepare("INSERT INTO users (username, domain, email, password_hash) VALUES (?, ?, ?, ?)");
            $stmt->execute([$username, DOMAIN, $email, $passwordHash]);
            
            successResponse([
                'message' => 'Registration successful',
                'email' => $email,
                'user_id' => $db->lastInsertId()
            ]);
        } catch (PDOException $e) {
            if (strpos($e->getMessage(), 'UNIQUE constraint failed') !== false) {
                errorResponse('Username already exists on this domain');
            }
            error_log("Registration error: " . $e->getMessage());
            errorResponse('Registration failed - please try again', 500);
        }
    }
    
    // POST /login - Authenticate user
    elseif ($path === '/login' && $requestMethod === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            errorResponse('Invalid JSON input');
        }
        
        $email = sanitizeInput($input['email'] ?? '');
        $password = $input['password'] ?? '';
        
        if (!validateEmail($email) || empty($password)) {
            errorResponse('Invalid credentials', 401);
        }
        
        try {
            $db = getDB();
            $stmt = $db->prepare("SELECT id, email, password_hash, username, domain FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user || !password_verify($password, $user['password_hash'])) {
                // Sleep briefly to prevent timing attacks
                usleep(500000); // 0.5 seconds
                errorResponse('Invalid credentials', 401);
            }
            
            $token = generateJWT($user['id'], $user['email']);
            
            successResponse([
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'username' => $user['username'],
                    'domain' => $user['domain']
                ],
                'message' => 'Login successful'
            ]);
        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            errorResponse('Login failed - please try again', 500);
        }
    }
    
    // POST /send - Send encrypted message
    elseif ($path === '/send' && $requestMethod === 'POST') {
        $authUser = getAuthUser();
        if (!$authUser) {
            errorResponse('Unauthorized - please login', 401);
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            errorResponse('Invalid JSON input');
        }
        
        $to = sanitizeInput($input['to'] ?? '');
        $subject = sanitizeInput($input['subject'] ?? '');
        $encryptedContent = $input['encrypted_content'] ?? '';
        $encryptedAttachments = $input['encrypted_attachments'] ?? null;
        
        // Validation
        if (!validateEmail($to)) {
            errorResponse('Invalid recipient email address');
        }
        
        if (empty($subject) || empty($encryptedContent)) {
            errorResponse('Subject and content are required');
        }
        
        if (strlen($encryptedContent) > 10000000) { // 10MB limit
            errorResponse('Message content too large (max 10MB)');
        }
        
        // Check if recipient exists
        $db = getDB();
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$to]);
        if (!$stmt->fetch()) {
            errorResponse('Recipient does not exist - they need to register first');
        }
        
        // Store encrypted attachments as JSON
        $attachmentsJson = null;
        if ($encryptedAttachments && is_array($encryptedAttachments)) {
            $attachmentsJson = json_encode($encryptedAttachments);
            if (strlen($attachmentsJson) > 50000000) { // 50MB limit for attachments
                errorResponse('Attachments too large (max 50MB total)');
            }
        }
        
        try {
            $stmt = $db->prepare("
                INSERT INTO messages (from_user, to_user, subject, encrypted_content, encrypted_attachments) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $authUser['email'],
                $to,
                $subject,
                $encryptedContent,
                $attachmentsJson
            ]);
            
            successResponse([
                'message' => 'Message sent successfully',
                'message_id' => $db->lastInsertId(),
                'encrypted' => true
            ]);
        } catch (PDOException $e) {
            error_log("Send message error: " . $e->getMessage());
            errorResponse('Failed to send message - please try again', 500);
        }
    }
    
    // GET /messages - Get inbox or trash messages
    elseif ($path === '/messages' && $requestMethod === 'GET') {
        $authUser = getAuthUser();
        if (!$authUser) {
            errorResponse('Unauthorized - please login', 401);
        }
        
        $type = $_GET['type'] ?? 'inbox';
        $isDeleted = ($type === 'trash') ? 1 : 0;
        
        try {
            $db = getDB();
            $stmt = $db->prepare("
                SELECT 
                    id, 
                    from_user, 
                    to_user, 
                    subject, 
                    created_at,
                    CASE WHEN encrypted_attachments IS NOT NULL AND encrypted_attachments != '' THEN 
                        (LENGTH(encrypted_attachments) - LENGTH(REPLACE(encrypted_attachments, 'filename', ''))) / LENGTH('filename')
                    ELSE 0 END as attachments_count
                FROM messages 
                WHERE to_user = ? AND is_deleted = ?
                ORDER BY created_at DESC
                LIMIT 1000
            ");
            $stmt->execute([$authUser['email'], $isDeleted]);
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            successResponse([
                'messages' => $messages,
                'count' => count($messages),
                'type' => $type
            ]);
        } catch (PDOException $e) {
            error_log("Load messages error: " . $e->getMessage());
            errorResponse('Failed to load messages - please try again', 500);
        }
    }
    
    // GET /message/{id} - Get single message details
    elseif (preg_match('#^/message/(\d+)$#', $path, $matches) && $requestMethod === 'GET') {
        $authUser = getAuthUser();
        if (!$authUser) {
            errorResponse('Unauthorized - please login', 401);
        }
        
        $id = $matches[1];
        
        try {
            $db = getDB();
            $stmt = $db->prepare("
                SELECT id, from_user, to_user, subject, encrypted_content, encrypted_attachments, created_at, is_deleted
                FROM messages 
                WHERE id = ? AND to_user = ?
            ");
            $stmt->execute([$id, $authUser['email']]);
            $message = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$message) {
                errorResponse('Message not found or access denied', 404);
            }
            
            successResponse(['message' => $message]);
        } catch (PDOException $e) {
            error_log("Load message error: " . $e->getMessage());
            errorResponse('Failed to load message - please try again', 500);
        }
    }
    
    // POST /message/{id}/trash - Move message to trash
    elseif (preg_match('#^/message/(\d+)/trash$#', $path, $matches) && $requestMethod === 'POST') {
        $authUser = getAuthUser();
        if (!$authUser) {
            errorResponse('Unauthorized - please login', 401);
        }
        
        $id = $matches[1];
        
        try {
            $db = getDB();
            $stmt = $db->prepare("UPDATE messages SET is_deleted = 1 WHERE id = ? AND to_user = ? AND is_deleted = 0");
            $stmt->execute([$id, $authUser['email']]);
            
            if ($stmt->rowCount() === 0) {
                errorResponse('Message not found or already in trash', 404);
            }
            
            successResponse(['message' => 'Message moved to trash successfully']);
        } catch (PDOException $e) {
            error_log("Move to trash error: " . $e->getMessage());
            errorResponse('Failed to move message - please try again', 500);
        }
    }
    
    // DELETE /message/{id} - Permanently delete message
    elseif (preg_match('#^/message/(\d+)$#', $path, $matches) && $requestMethod === 'DELETE') {
        $authUser = getAuthUser();
        if (!$authUser) {
            errorResponse('Unauthorized - please login', 401);
        }
        
        $id = $matches[1];
        
        try {
            $db = getDB();
            $stmt = $db->prepare("DELETE FROM messages WHERE id = ? AND to_user = ? AND is_deleted = 1");
            $stmt->execute([$id, $authUser['email']]);
            
            if ($stmt->rowCount() === 0) {
                errorResponse('Message not found or not in trash (move to trash first)', 404);
            }
            
            successResponse(['message' => 'Message deleted permanently']);
        } catch (PDOException $e) {
            error_log("Delete message error: " . $e->getMessage());
            errorResponse('Failed to delete message - please try again', 500);
        }
    }
    
    // 404 - Endpoint not found
    else {
        error_log("404 - Endpoint not found: $requestMethod $path");
        errorResponse("Endpoint not found: $path (Method: $requestMethod)", 404);
    }
    
} catch (Exception $e) {
    error_log("Unexpected error: " . $e->getMessage());
    errorResponse('Internal server error - please check logs', 500);
}
?>