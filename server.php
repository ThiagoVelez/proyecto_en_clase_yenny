<?php
if (!isset($_SERVER['SERVER_NAME'])) {
    $_SERVER['SERVER_NAME'] = 'localhost';
}
if (!isset($_SERVER['SERVER_PORT'])) {
    $_SERVER['SERVER_PORT'] = '80';
}

require_once "vendor/econea/nusoap/src/nusoap.php";

// Capturar el payload XML de la petición cruda para análisis de cabeceras de seguridad
$POST_DATA = isset($GLOBALS['RAW_POST_DATA']) ? $GLOBALS['RAW_POST_DATA'] : file_get_contents("php://input");

// 1. Configuración del Servidor SOAP
$namespace = "InsertUserSOAP";
$server = new soap_server();
$server->soap_defencoding = 'UTF-8';
$server->xml_encoding = 'UTF-8';
$server->decode_utf8 = false;
$server->configureWSDL('SoapService', $namespace);

// Helper para asegurar codificación UTF-8 en datos de entrada
function to_utf8($val) {
    if (is_string($val)) {
        if (!mb_check_encoding($val, 'UTF-8')) {
            return mb_convert_encoding($val, 'UTF-8', 'ISO-8859-1, Windows-1252');
        }
        return $val;
    }
    return $val;
}

// 2. Configuración de Base de Datos
$host = "127.0.0.1";
$port = "3306";
$dbname = "soap_cptec";
$username = "root";
$password = "";

$dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";

// 3. Conexión PDO con manejo de excepciones
try {
    $pdo = new PDO($dsn, $username, $password, array(
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
    ));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log("Fallo de conexion a base de datos: " . $e->getMessage());
    $pdo = null;
}

// Helper para verificar contraseñas encriptadas (password_hash / SHA256 / SHA1 / MD5)
function verify_password($input_password, $stored_hash) {
    if (empty($input_password) || empty($stored_hash)) {
        return false;
    }
    // 1. Verificación nativa de PHP (password_hash)
    if (password_verify($input_password, $stored_hash)) {
        return true;
    }
    // 2. Verificación SHA-256 (como los generados con SHA2(..., 256) en MySQL)
    if (hash('sha256', $input_password) === strtolower($stored_hash) || hash('sha256', $input_password) === $stored_hash) {
        return true;
    }
    // 3. Fallback a SHA1 y MD5 por compatibilidad
    if (sha1($input_password) === $stored_hash || md5($input_password) === $stored_hash) {
        return true;
    }
    return false;
}

// Helper para extraer credenciales de WS-Security (<wsse:Security>) o token del Header
function get_ws_security_header() {
    global $server, $POST_DATA;

    $username = null;
    $password = null;
    $token = null;

    $xmlInput = !empty($POST_DATA) ? $POST_DATA : file_get_contents("php://input");

    // 1. Extraer desde el XML crudo en la sección <Header>
    if (!empty($xmlInput) && preg_match('/<[a-zA-Z0-9_\-:]*Header[^>]*>(.*?)<\/[a-zA-Z0-9_\-:]*Header>/is', $xmlInput, $hMatches)) {
        $headerXml = $hMatches[1];

        // Extraer <wsse:Username> o <Username>
        if (preg_match('/<[a-zA-Z0-9_\-:]*Username[^>]*>([^<]+)<\/[a-zA-Z0-9_\-:]*Username>/i', $headerXml, $m)) {
            $username = trim($m[1]);
        }
        // Extraer <wsse:Password> o <Password>
        if (preg_match('/<[a-zA-Z0-9_\-:]*Password[^>]*>([^<]+)<\/[a-zA-Z0-9_\-:]*Password>/i', $headerXml, $m)) {
            $password = trim($m[1]);
        }
        // Extraer <token>
        if (preg_match('/<[a-zA-Z0-9_\-:]*token[^>]*>([^<]+)<\/[a-zA-Z0-9_\-:]*token>/i', $headerXml, $m)) {
            $token = trim($m[1]);
        }
    }

    // 2. Extraer desde $server->requestHeader de NuSOAP si no se halló en XML directo
    if (empty($username) && !empty($server->requestHeader) && is_array($server->requestHeader)) {
        array_walk_recursive($server->requestHeader, function($val, $key) use (&$username, &$password, &$token) {
            $cleanKey = strtolower(basename(str_replace(':', '/', $key)));
            if ($cleanKey === 'username' && empty($username)) $username = trim((string)$val);
            if ($cleanKey === 'password' && empty($password)) $password = trim((string)$val);
            if ($cleanKey === 'token' && empty($token)) $token = trim((string)$val);
        });
    }

    // 3. Extraer desde cabeceras HTTP alternativas
    if (empty($token) && empty($username)) {
        if (!empty($_SERVER['HTTP_TOKEN'])) {
            $token = trim($_SERVER['HTTP_TOKEN']);
        } elseif (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            if (preg_match('/Bearer\s+(.*)$/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) {
                $token = trim($m[1]);
            }
        }
    }

    return array(
        'username' => $username,
        'password' => $password,
        'token'    => $token
    );
}

// Validador de seguridad para WS-Security y Tokens
function validate_security_header($fallbackParam = null) {
    global $pdo;

    if (!$pdo) {
        return false;
    }

    // Si se pasa token directo por parámetro o dentro de array
    if (!empty($fallbackParam) && is_string($fallbackParam) && trim($fallbackParam) !== '') {
        if (validate_token_in_db(trim($fallbackParam))) {
            return true;
        }
    }

    $cred = get_ws_security_header();
    $username = $cred['username'];
    $password = $cred['password'];
    $token    = $cred['token'];

    // Caso 1: Se envió token directo en el Header (<token>...</token> o cabecera HTTP)
    if (!empty($token)) {
        if (validate_token_in_db($token)) {
            return true;
        }
    }

    // Caso 2: WS-SECURITY estándar con <wsse:Security><wsse:UsernameToken>
    if (!empty($username) && !empty($password)) {
        try {
            $stmt = $pdo->prepare("SELECT id, user_name, password, token FROM user WHERE user_name = :user_name LIMIT 1");
            $stmt->bindParam(':user_name', $username);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // 2.1 Verificar si en el Password del UsernameToken viene el Token generado
                if (!empty($user['token']) && $user['token'] === $password) {
                    return true;
                }
                // 2.2 Verificar si coincide con la contraseña encriptada del usuario
                if (verify_password($password, $user['password'])) {
                    // Generar token criptográficamente seguro si no lo tiene
                    if (empty($user['token'])) {
                        $newToken = bin2hex(random_bytes(32));
                        $up = $pdo->prepare("UPDATE user SET token = :token, token_date = NOW() WHERE id = :id");
                        $up->bindParam(':token', $newToken);
                        $up->bindParam(':id', $user['id']);
                        $up->execute();
                    }
                    return true;
                }
            }
        } catch (PDOException $e) {
            return false;
        }
    }

    // Caso 3: El token vino dentro del tag <wsse:Password> sin especificar username
    if (!empty($password) && empty($username)) {
        if (validate_token_in_db($password)) {
            return true;
        }
    }

    return false;
}

// Helper para validar un token en la base de datos
function validate_token_in_db($token) {
    global $pdo;
    if (empty($token) || !$pdo) return false;
    try {
        $stmt = $pdo->prepare("SELECT id, user_name FROM user WHERE token = :token AND token IS NOT NULL LIMIT 1");
        $clean = trim($token);
        $stmt->bindParam(':token', $clean);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC) ? true : false;
    } catch (PDOException $e) {
        return false;
    }
}

// 4. Definición de tipos complejos
$server->wsdl->addComplexType(
    'InsertUser',
    'complexType',
    'struct',
    'all',
    '',
    array(
        'user_name'   => array('name' => 'user_name', 'type' => 'xsd:string'),
        'lastname'    => array('name' => 'lastname', 'type' => 'xsd:string'),
        'doc_type_id' => array('name' => 'doc_type_id', 'type' => 'xsd:int'),
        'num_doc'     => array('name' => 'num_doc', 'type' => 'xsd:string'),
        'password'    => array('name' => 'password', 'type' => 'xsd:string'),
        'address'     => array('name' => 'address', 'type' => 'xsd:string'),
        'phone'       => array('name' => 'phone', 'type' => 'xsd:string')
    )
);

$server->wsdl->addComplexType(
    'UpdateUser',
    'complexType',
    'struct',
    'all',
    '',
    array(
        'id'          => array('name' => 'id', 'type' => 'xsd:int'),
        'user_name'   => array('name' => 'user_name', 'type' => 'xsd:string'),
        'lastname'    => array('name' => 'lastname', 'type' => 'xsd:string'),
        'doc_type_id' => array('name' => 'doc_type_id', 'type' => 'xsd:int'),
        'num_doc'     => array('name' => 'num_doc', 'type' => 'xsd:string'),
        'password'    => array('name' => 'password', 'type' => 'xsd:string'),
        'address'     => array('name' => 'address', 'type' => 'xsd:string'),
        'phone'       => array('name' => 'phone', 'type' => 'xsd:string')
    )
);

$server->wsdl->addComplexType(
    'UserData',
    'complexType',
    'struct',
    'all',
    '',
    array(
        'id'           => array('name' => 'id', 'type' => 'xsd:int'),
        'user_name'    => array('name' => 'user_name', 'type' => 'xsd:string'),
        'lastname'     => array('name' => 'lastname', 'type' => 'xsd:string'),
        'doc_type_id'  => array('name' => 'doc_type_id', 'type' => 'xsd:int'),
        'num_doc'      => array('name' => 'num_doc', 'type' => 'xsd:string'),
        'address'      => array('name' => 'address', 'type' => 'xsd:string'),
        'phone'        => array('name' => 'phone', 'type' => 'xsd:string'),
        'created_date' => array('name' => 'created_date', 'type' => 'xsd:string')
    )
);

$server->wsdl->addComplexType(
    'UserArray',
    'complexType',
    'array',
    '',
    'SOAP-ENC:Array',
    array(),
    array(
        array('ref' => 'SOAP-ENC:arrayType', 'wsdl:arrayType' => 'tns:UserData[]')
    ),
    'tns:UserData'
);

// 5. Registro de operaciones del servicio SOAP

// 5.1 Servicio de Login y Generación de Token con RANDOM_BYTES()
$server->register(
    'LoginService',
    array(
        'user_name' => 'xsd:string',
        'password'  => 'xsd:string'
    ),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Iniciar sesion y generar token criptografico con random_bytes'
);

// 5.2 Servicio de Validación de Token
$server->register(
    'ValidateTokenService',
    array('token' => 'xsd:string'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Validar autenticidad de un token'
);

// 5.3 Operaciones CRUD protegidas con WS-SECURITY en el SOAP:HEADER
$server->register(
    'InsertUserService',
    array('data' => 'tns:InsertUser'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Insertar un usuario (requiere WS-Security en el Header)'
);

$server->register(
    'UpdateUserService',
    array('data' => 'tns:UpdateUser'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Actualizar un usuario existente (requiere WS-Security en el Header)'
);

$server->register(
    'DeleteUserService',
    array('id' => 'xsd:int'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Eliminar un usuario por ID (requiere WS-Security en el Header)'
);

$server->register(
    'SelectUserService',
    array('id' => 'xsd:int'),
    array('return' => 'tns:UserData'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Seleccionar un usuario por ID (requiere WS-Security en el Header)'
);

$server->register(
    'ListUsersService',
    array(),
    array('return' => 'tns:UserArray'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Listar todos los usuarios (requiere WS-Security en el Header)'
);

// 6. Implementación de funciones del servicio

// 6.1 Iniciar sesión y Generar Token criptográficamente seguro
function LoginService($user_name, $password) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    $user_name = trim(to_utf8($user_name));
    $password  = trim(to_utf8($password));

    if (empty($user_name) || empty($password)) {
        return "-1";
    }

    try {
        $stmt = $pdo->prepare("SELECT id, user_name, password FROM user WHERE user_name = :user_name LIMIT 1");
        $stmt->bindParam(':user_name', $user_name);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return "-1";
        }

        // Validación de contraseña encriptada
        if (!verify_password($password, $user['password'])) {
            return "-1";
        }

        // Generación del token según diapositiva de clase:
        // RANDOM_BYTES(32) genera bytes criptográficamente seguros y BIN2HEX() los convierte a hexadecimal
        $token = bin2hex(random_bytes(32));

        // Guardar el token generado en la base de datos
        $updateStmt = $pdo->prepare("UPDATE user SET token = :token, token_date = NOW() WHERE id = :id");
        $updateStmt->bindParam(':token', $token);
        $updateStmt->bindParam(':id', $user['id']);
        $updateStmt->execute();

        return $token;

    } catch (PDOException $e) {
        return "-1";
    }
}

// 6.2 Validar Token
function ValidateTokenService($token = null) {
    if (validate_security_header($token)) {
        return "1";
    }
    return "-1";
}

// 6.3 Insertar usuario (Protegido por WS-Security en el Header)
function InsertUserService($data) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    // Validar autenticación WS-Security en el Header
    if (!validate_security_header($data['token'] ?? null)) {
        return "-1"; // Acceso no autorizado
    }

    // Validación de campos requeridos
    if (
        empty($data['user_name']) || trim($data['user_name']) === '' ||
        empty($data['lastname']) || trim($data['lastname']) === '' ||
        !isset($data['doc_type_id']) || !is_numeric($data['doc_type_id']) || intval($data['doc_type_id']) <= 0 ||
        empty($data['num_doc']) || trim($data['num_doc']) === '' ||
        empty($data['password']) || trim($data['password']) === ''
    ) {
        return "-1";
    }

    try {
        $sql = "INSERT INTO user (user_name, lastname, doc_type_id, num_doc, password, address, phone, created_date)
                VALUES (:user_name, :lastname, :doc_type_id, :num_doc, :password, :address, :phone, NOW())";
        
        $stmt = $pdo->prepare($sql);
        $user_name   = to_utf8(trim($data['user_name']));
        $lastname    = to_utf8(trim($data['lastname']));
        $doc_type_id = intval($data['doc_type_id']);
        $num_doc     = to_utf8(trim($data['num_doc']));
        // Encriptar la contraseña usando algoritmo criptográfico seguro (bcrypt)
        $password_hash = password_hash(trim($data['password']), PASSWORD_DEFAULT);
        $address     = isset($data['address']) ? to_utf8(trim($data['address'])) : '';
        $phone       = isset($data['phone']) ? to_utf8(trim($data['phone'])) : '';

        $stmt->bindParam(':user_name', $user_name);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':doc_type_id', $doc_type_id);
        $stmt->bindParam(':num_doc', $num_doc);
        $stmt->bindParam(':password', $password_hash);
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':phone', $phone);

        $stmt->execute();
        return "Se ha guardado correctamente";

    } catch (PDOException $e) {
        return "-1";
    }
}

// 6.4 Actualizar usuario (Protegido por WS-Security en el Header)
function UpdateUserService($data) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    // Validar autenticación WS-Security en el Header
    if (!validate_security_header($data['token'] ?? null)) {
        return "-1";
    }

    // Validación de ID
    if (empty($data['id']) || !is_numeric($data['id']) || intval($data['id']) <= 0) {
        return "-1";
    }

    // Validación de campos requeridos
    if (
        empty($data['user_name']) || trim($data['user_name']) === '' ||
        empty($data['lastname']) || trim($data['lastname']) === '' ||
        !isset($data['doc_type_id']) || !is_numeric($data['doc_type_id']) || intval($data['doc_type_id']) <= 0 ||
        empty($data['num_doc']) || trim($data['num_doc']) === ''
    ) {
        return "-1";
    }

    try {
        $check = $pdo->prepare("SELECT id FROM user WHERE id = :id");
        $check->execute(array(':id' => intval($data['id'])));
        if ($check->rowCount() === 0) {
            return "-1";
        }

        $hasNewPass = !empty($data['password']) && trim($data['password']) !== '';
        if ($hasNewPass) {
            $sql = "UPDATE user SET 
                        user_name = :user_name,
                        lastname = :lastname,
                        doc_type_id = :doc_type_id,
                        num_doc = :num_doc,
                        password = :password,
                        address = :address,
                        phone = :phone
                    WHERE id = :id";
        } else {
            $sql = "UPDATE user SET 
                        user_name = :user_name,
                        lastname = :lastname,
                        doc_type_id = :doc_type_id,
                        num_doc = :num_doc,
                        address = :address,
                        phone = :phone
                    WHERE id = :id";
        }
        
        $stmt = $pdo->prepare($sql);
        $id          = intval($data['id']);
        $user_name   = to_utf8(trim($data['user_name']));
        $lastname    = to_utf8(trim($data['lastname']));
        $doc_type_id = intval($data['doc_type_id']);
        $num_doc     = to_utf8(trim($data['num_doc']));
        $address     = isset($data['address']) ? to_utf8(trim($data['address'])) : '';
        $phone       = isset($data['phone']) ? to_utf8(trim($data['phone'])) : '';

        $stmt->bindParam(':id', $id);
        $stmt->bindParam(':user_name', $user_name);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':doc_type_id', $doc_type_id);
        $stmt->bindParam(':num_doc', $num_doc);
        if ($hasNewPass) {
            $password_hash = password_hash(trim($data['password']), PASSWORD_DEFAULT);
            $stmt->bindParam(':password', $password_hash);
        }
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':phone', $phone);

        $stmt->execute();
        return "Usuario actualizado correctamente";

    } catch (PDOException $e) {
        return "-1";
    }
}

// 6.5 Eliminar usuario (Protegido por WS-Security en el Header)
function DeleteUserService($id) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    if (is_array($id)) {
        $id = $id['id'] ?? null;
    }

    // Validar autenticación WS-Security en el Header
    if (!validate_security_header()) {
        return "-1";
    }

    if (empty($id) || !is_numeric($id) || intval($id) <= 0) {
        return "-1";
    }

    try {
        $check = $pdo->prepare("SELECT id FROM user WHERE id = :id");
        $check->execute(array(':id' => intval($id)));
        if ($check->rowCount() === 0) {
            return "-1";
        }

        $stmt = $pdo->prepare("DELETE FROM user WHERE id = :id");
        $userId = intval($id);
        $stmt->bindParam(':id', $userId);
        $stmt->execute();

        return "Usuario eliminado correctamente";

    } catch (PDOException $e) {
        return "-1";
    }
}

// 6.6 Seleccionar usuario por ID (Protegido por WS-Security en el Header)
function SelectUserService($id) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    if (is_array($id)) {
        $id = $id['id'] ?? null;
    }

    // Validar autenticación WS-Security en el Header
    if (!validate_security_header()) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    if (empty($id) || !is_numeric($id) || intval($id) <= 0) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    try {
        $stmt = $pdo->prepare("SELECT id, user_name, lastname, doc_type_id, num_doc, address, phone, created_date FROM user WHERE id = :id");
        $stmt->execute(array(':id' => intval($id)));
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
        }

        return array(
            'id'           => (int)$user['id'],
            'user_name'    => (string)$user['user_name'],
            'lastname'     => (string)$user['lastname'],
            'doc_type_id'  => (int)$user['doc_type_id'],
            'num_doc'      => (string)$user['num_doc'],
            'address'      => (string)($user['address'] ?? ''),
            'phone'        => (string)($user['phone'] ?? ''),
            'created_date' => (string)($user['created_date'] ?? '')
        );

    } catch (PDOException $e) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }
}

// 6.7 Listar todos los usuarios (Protegido por WS-Security en el Header)
function ListUsersService($param = null) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    // Validar autenticación WS-Security en el Header
    if (!validate_security_header(is_string($param) ? $param : null)) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    try {
        $stmt = $pdo->query("SELECT id, user_name, lastname, doc_type_id, num_doc, address, phone, created_date FROM user ORDER BY id ASC");
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($users)) {
            return array();
        }

        $result = array();
        foreach ($users as $u) {
            $result[] = array(
                'id'           => (int)$u['id'],
                'user_name'    => (string)$u['user_name'],
                'lastname'     => (string)$u['lastname'],
                'doc_type_id'  => (int)$u['doc_type_id'],
                'num_doc'      => (string)$u['num_doc'],
                'address'      => (string)($u['address'] ?? ''),
                'phone'        => (string)($u['phone'] ?? ''),
                'created_date' => (string)($u['created_date'] ?? '')
            );
        }

        return $result;

    } catch (PDOException $e) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }
}

// 7. Procesar y responder a la solicitud SOAP
if (!defined('TESTING_MODE')) {
    $server->service($POST_DATA);
    exit();
}
