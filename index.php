<?php
session_start();

// Database configuration (SQLite for simplicity)
class Database {
    private $pdo;
    
    public function __construct() {
        try {
            $this->pdo = new PDO('sqlite:cryptovault.db');
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->createTables();
        } catch (PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }
    
    private function createTables() {
        $sql = "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )";
        
        $this->pdo->exec($sql);
        
        $sql = "CREATE TABLE IF NOT EXISTS encryption_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            algorithm TEXT NOT NULL,
            input_text TEXT NOT NULL,
            output_text TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )";
        
        $this->pdo->exec($sql);
    }
    
    public function getPDO() {
        return $this->pdo;
    }
}

// User authentication class
class Auth {
    private $db;
    
    public function __construct($database) {
        $this->db = $database->getPDO();
    }
    
    public function register($email, $password) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format");
        }
        
        if (strlen($password) < 6) {
            throw new Exception("Password must be at least 6 characters long");
        }
        
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        try {
            $stmt = $this->db->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
            $stmt->execute([$email, $hashedPassword]);
            return true;
        } catch (PDOException $e) {
            if ($e->getCode() == 23000) {
                throw new Exception("Email already registered");
            }
            throw new Exception("Registration failed");
        }
    }
    
    public function login($email, $password) {
        $stmt = $this->db->prepare("SELECT id, email, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_email'] = $user['email'];
            return true;
        }
        
        throw new Exception("Invalid email or password");
    }
    
    public function logout() {
        session_destroy();
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['user_id']);
    }
    
    public function getCurrentUser() {
        if ($this->isLoggedIn()) {
            return [
                'id' => $_SESSION['user_id'],
                'email' => $_SESSION['user_email']
            ];
        }
        return null;
    }
}

// Encryption algorithms class
class CryptoEngine {
    private $db;
    
    public function __construct($database) {
        $this->db = $database->getPDO();
    }
    
    public function encrypt($text, $algorithm, $key = '') {
        switch ($algorithm) {
            case 'caesar':
                return $this->caesarCipher($text, intval($key) ?: 3);
            case 'vigenere':
                return $this->vigenereCipher($text, $key, true);
            case 'atbash':
                return $this->atbashCipher($text);
            case 'base64':
                return base64_encode($text);
            case 'reverse':
                return strrev($text);
            case 'rot13':
                return str_rot13($text);
            case 'aes':
                return $this->aesEncrypt($text, $key);
            default:
                throw new Exception("Unknown encryption algorithm");
        }
    }
    
    public function decrypt($text, $algorithm, $key = '') {
        switch ($algorithm) {
            case 'caesar':
                return $this->caesarCipher($text, -(intval($key) ?: 3));
            case 'vigenere':
                return $this->vigenereCipher($text, $key, false);
            case 'atbash':
                return $this->atbashCipher($text);
            case 'base64':
                return base64_decode($text);
            case 'reverse':
                return strrev($text);
            case 'rot13':
                return str_rot13($text);
            case 'aes':
                return $this->aesDecrypt($text, $key);
            default:
                throw new Exception("Unknown decryption algorithm");
        }
    }
    
    private function caesarCipher($text, $shift) {
        $result = '';
        for ($i = 0; $i < strlen($text); $i++) {
            $char = $text[$i];
            if (ctype_alpha($char)) {
                $ascii = ord($char);
                $base = ctype_upper($char) ? 65 : 97;
                $result .= chr(($ascii - $base + $shift + 26) % 26 + $base);
            } else {
                $result .= $char;
            }
        }
        return $result;
    }
    
    private function vigenereCipher($text, $key, $encrypt) {
        if (empty($key)) {
            throw new Exception("Vigenère cipher requires a key");
        }
        
        $result = '';
        $keyUpper = strtoupper($key);
        $keyIndex = 0;
        
        for ($i = 0; $i < strlen($text); $i++) {
            $char = $text[$i];
            if (ctype_alpha($char)) {
                $isUpper = ctype_upper($char);
                $charCode = ord(strtoupper($char)) - 65;
                $keyChar = ord($keyUpper[$keyIndex % strlen($keyUpper)]) - 65;
                
                if ($encrypt) {
                    $newChar = ($charCode + $keyChar) % 26;
                } else {
                    $newChar = ($charCode - $keyChar + 26) % 26;
                }
                
                $result .= $isUpper ? chr($newChar + 65) : chr($newChar + 97);
                $keyIndex++;
            } else {
                $result .= $char;
            }
        }
        return $result;
    }
    
    private function atbashCipher($text) {
        $result = '';
        for ($i = 0; $i < strlen($text); $i++) {
            $char = $text[$i];
            if (ctype_alpha($char)) {
                $ascii = ord($char);
                if (ctype_upper($char)) {
                    $result .= chr(90 - ($ascii - 65));
                } else {
                    $result .= chr(122 - ($ascii - 97));
                }
            } else {
                $result .= $char;
            }
        }
        return $result;
    }
    
    private function aesEncrypt($text, $key) {
        if (empty($key)) {
            throw new Exception("AES encryption requires a key");
        }
        
        $key = hash('sha256', $key, true);
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    private function aesDecrypt($text, $key) {
        if (empty($key)) {
            throw new Exception("AES decryption requires a key");
        }
        
        $key = hash('sha256', $key, true);
        $data = base64_decode($text);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }
    
    public function saveToHistory($userId, $algorithm, $inputText, $outputText, $action) {
        $stmt = $this->db->prepare("INSERT INTO encryption_history (user_id, algorithm, input_text, output_text, action) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$userId, $algorithm, $inputText, $outputText, $action]);
    }
    
    public function getHistory($userId, $limit = 10) {
        $stmt = $this->db->prepare("SELECT * FROM encryption_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?");
        $stmt->execute([$userId, $limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// Initialize classes
$database = new Database();
$auth = new Auth($database);
$crypto = new CryptoEngine($database);

// Handle form submissions
$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        if (isset($_POST['register'])) {
            $auth->register($_POST['email'], $_POST['password']);
            $message = "Registration successful! You can now login.";
            $messageType = "success";
        } elseif (isset($_POST['login'])) {
            $auth->login($_POST['email'], $_POST['password']);
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } elseif (isset($_POST['logout'])) {
            $auth->logout();
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } elseif (isset($_POST['encrypt']) || isset($_POST['decrypt'])) {
            if (!$auth->isLoggedIn()) {
                throw new Exception("Please login to use encryption tools");
            }
            
            $action = isset($_POST['encrypt']) ? 'encrypt' : 'decrypt';
            $algorithm = $_POST['algorithm'];
            $key = $_POST['crypto_key'] ?? '';
            $inputText = $_POST['input_text'];
            
            if ($action == 'encrypt') {
                $result = $crypto->encrypt($inputText, $algorithm, $key);
            } else {
                $result = $crypto->decrypt($inputText, $algorithm, $key);
            }
            
            $crypto->saveToHistory($auth->getCurrentUser()['id'], $algorithm, $inputText, $result, $action);
            
            $_POST['output_text'] = $result;
            $message = ucfirst($action) . "ion successful!";
            $messageType = "success";
        }
    } catch (Exception $e) {
        $message = $e->getMessage();
        $messageType = "error";
    }
}

// Algorithm information
$algorithms = [
    'caesar' => [
        'name' => 'Caesar Cipher',
        'description' => 'A simple substitution cipher where each letter is shifted by a fixed number of positions in the alphabet.',
        'key_required' => true,
        'key_type' => 'number'
    ],
    'vigenere' => [
        'name' => 'Vigenère Cipher',
        'description' => 'A polyalphabetic substitution cipher that uses a keyword to shift letters.',
        'key_required' => true,
        'key_type' => 'text'
    ],
    'atbash' => [
        'name' => 'Atbash Cipher',
        'description' => 'A substitution cipher where A becomes Z, B becomes Y, etc.',
        'key_required' => false,
        'key_type' => 'none'
    ],
    'base64' => [
        'name' => 'Base64 Encoding',
        'description' => 'Converts text to Base64 encoding. Not encryption but encoding.',
        'key_required' => false,
        'key_type' => 'none'
    ],
    'reverse' => [
        'name' => 'Reverse Text',
        'description' => 'Simply reverses the order of characters in the text.',
        'key_required' => false,
        'key_type' => 'none'
    ],
    'rot13' => [
        'name' => 'ROT13',
        'description' => 'A Caesar cipher with a fixed shift of 13.',
        'key_required' => false,
        'key_type' => 'none'
    ],
    'aes' => [
        'name' => 'AES-256 Encryption',
        'description' => 'Advanced Encryption Standard with 256-bit key. Very secure.',
        'key_required' => true,
        'key_type' => 'text'
    ]
];

$currentAlgorithm = $_POST['algorithm'] ?? 'caesar';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptoVault PHP - Encryption Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #2d3748;
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            color: #718096;
            font-size: 1.1em;
        }

        .message {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-weight: 600;
        }

        .message.success {
            background: #c6f6d5;
            border: 1px solid #9ae6b4;
            color: #2f855a;
        }

        .message.error {
            background: #fed7d7;
            border: 1px solid #fc8181;
            color: #c53030;
        }

        .auth-section {
            background: #f8fafc;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid #e2e8f0;
        }

        .auth-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }

        .auth-tab {
            flex: 1;
            padding: 12px 20px;
            background: #fff;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            cursor: pointer;
            text-align: center;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            color: #4a5568;
        }

        .auth-tab.active {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border-color: #667eea;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #4a5568;
            font-weight: 600;
        }

        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn {
            padding: 14px 20px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .btn-secondary {
            background: #e2e8f0;
            color: #4a5568;
        }

        .btn-danger {
            background: #e53e3e;
        }

        .user-info {
            background: #e6fffa;
            border: 1px solid #81e6d9;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .tool-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }

        .crypto-controls {
            background: #f8fafc;
            border-radius: 15px;
            padding: 25px;
            border: 1px solid #e2e8f0;
        }

        .crypto-controls h3 {
            color: #2d3748;
            margin-bottom: 20px;
            font-size: 1.3em;
        }

        .text-areas {
            background: #f8fafc;
            border-radius: 15px;
            padding: 25px;
            border: 1px solid #e2e8f0;
        }

        .text-areas textarea {
            height: 200px;
            font-family: 'Courier New', monospace;
            resize: vertical;
        }

        .algorithm-info {
            background: #fff5f5;
            border: 1px solid #feb2b2;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .algorithm-info h4 {
            color: #c53030;
            margin-bottom: 10px;
        }

        .algorithm-info p {
            color: #4a5568;
            line-height: 1.6;
        }

        .action-buttons {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }

        .btn-encrypt {
            background: linear-gradient(135deg, #48bb78, #38a169);
        }

        .btn-decrypt {
            background: linear-gradient(135deg, #ed8936, #dd6b20);
        }

        .btn-clear {
            background: linear-gradient(135deg, #4299e1, #3182ce);
        }

        .history-section {
            grid-column: 1 / -1;
            background: #f8fafc;
            border-radius: 15px;
            padding: 25px;
            border: 1px solid #e2e8f0;
            margin-top: 30px;
        }

        .history-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .history-table th, .history-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }

        .history-table th {
            background: #e2e8f0;
            font-weight: 600;
        }

        .history-table td {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }

            .tool-section {
                grid-template-columns: 1fr;
            }

            .action-buttons {
                flex-direction: column;
            }

            .header h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 CryptoVault PHP</h1>
            <p>Professional encryption and decryption tool with user management</p>
        </div>

        <?php if ($message): ?>
        <div class="message <?php echo $messageType; ?>">
            <?php echo htmlspecialchars($message); ?>
        </div>
        <?php endif; ?>

        <?php if (!$auth->isLoggedIn()): ?>
        <!-- Authentication Section -->
        <div class="auth-section">
            <div class="auth-tabs">
                <a href="#" class="auth-tab active" onclick="showTab('login')">Login</a>
                <a href="#" class="auth-tab" onclick="showTab('register')">Register</a>
            </div>

            <div id="loginForm">
                <form method="post">
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit" name="login" class="btn">Login</button>
                </form>
            </div>

            <div id="registerForm" style="display: none;">
                <form method="post">
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>Password (min 6 characters)</label>
                        <input type="password" name="password" required minlength="6">
                    </div>
                    <button type="submit" name="register" class="btn">Register</button>
                </form>
            </div>
        </div>
        <?php else: ?>
        <!-- Tool Section -->
        <div class="user-info">
            <span>Welcome, <?php echo htmlspecialchars($auth->getCurrentUser()['email']); ?></span>
            <form method="post" style="margin: 0;">
                <button type="submit" name="logout" class="btn btn-danger">Logout</button>
            </form>
        </div>

        <form method="post">
            <div class="tool-section">
                <div class="crypto-controls">
                    <h3>🔧 Encryption Settings</h3>
                    
                    <div class="form-group">
                        <label>Algorithm</label>
                        <select name="algorithm" id="algorithm" onchange="updateAlgorithmInfo()">
                            <?php foreach ($algorithms as $key => $algo): ?>
                            <option value="<?php echo $key; ?>" <?php echo $currentAlgorithm == $key ? 'selected' : ''; ?>>
                                <?php echo $algo['name']; ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Key/Shift Value</label>
                        <input type="text" name="crypto_key" value="<?php echo htmlspecialchars($_POST['crypto_key'] ?? ''); ?>" placeholder="Enter key or shift value">
                    </div>

                    <div class="algorithm-info" id="algorithmInfo">
                        <h4><?php echo $algorithms[$currentAlgorithm]['name']; ?></h4>
                        <p><?php echo $algorithms[$currentAlgorithm]['description']; ?></p>
                        <?php if ($algorithms[$currentAlgorithm]['key_required']): ?>
                        <p><strong>Key required:</strong> <?php echo ucfirst($algorithms[$currentAlgorithm]['key_type']); ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="action-buttons">
                        <button type="submit" name="encrypt" class="btn btn-encrypt">🔒 Encrypt</button>
                        <button type="submit" name="decrypt" class="btn btn-decrypt">🔓 Decrypt</button>
                        <button type="button" onclick="clearText()" class="btn btn-clear">🧹 Clear</button>
                    </div>
                </div>

                <div class="text-areas">
                    <h3>📝 Text Processing</h3>
                    
                    <div class="form-group">
                        <label>Input Text</label>
                        <textarea name="input_text" id="inputText" placeholder="Enter your text here..."><?php echo htmlspecialchars($_POST['input_text'] ?? ''); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Output Text</label>
                        <textarea id="outputText" readonly placeholder="Encrypted/Decrypted text will appear here..."><?php echo htmlspecialchars($_POST['output_text'] ?? ''); ?></textarea>
                    </div>
                </div>
            </div>
        </form>

        <!-- History Section -->
        <div class="history-section">
            <h3>📊 Recent Activity</h3>
            <?php
            $history = $crypto->getHistory($auth->getCurrentUser()['id']);
            if ($history):
            ?>
            <table class="history-table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Algorithm</th>
                        <th>Action</th>
                        <th>Input Preview</th>
                        <th>Output Preview</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($history as $record): ?>
                    <tr>
                        <td><?php echo date('M j, Y H:i', strtotime($record['created_at'])); ?></td>
                        <td><?php echo htmlspecialchars($record['algorithm']); ?></td>
                        <td><?php echo ucfirst($record['action']); ?></td>
                        <td title="<?php echo htmlspecialchars($record['input_text']); ?>">
                            <?php echo htmlspecialchars(substr($record['input_text'], 0, 50) . (strlen($record['input_text']) > 50 ? '...' : '')); ?>
                        </td>
                        <td title="<?php echo htmlspecialchars($record['output_text']); ?>">
                            <?php echo htmlspecialchars(substr($record['output_text'], 0, 50) . (strlen($record['output_text']) > 50 ? '...' : '')); ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <p>No encryption history yet. Start encrypting text to see your activity here!</p>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <script>
        const algorithms = <?php echo json_encode($algorithms); ?>;

        function showTab(tab) {
            document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
            document.querySelector(`[onclick="showTab('${tab}')"]`).classList.add('active');
            
            document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
            document.getElementById('registerForm').style.display = tab === 'register' ? 'block' : 'none';
        }

        function updateAlgorithmInfo() {
            const algorithm = document.getElementById('algorithm').value;
            const info = algorithms[algorithm];
            
            document.getElementById('algorithmInfo').innerHTML = `
                <h4>${info.name}</h4>
                <p>${info.description}</p>
                ${info.key_required ? `<p><strong>Key required:</strong> ${info.key_type.charAt(0).toUpperCase() + info.key_type.slice(1)}</p>` : ''}
            `;
        }

        function clearText() {
            document.getElementById('inputText').value = '';
            document.getElementById('outputText').value = '';
        }
    </script>
</body>
</html>