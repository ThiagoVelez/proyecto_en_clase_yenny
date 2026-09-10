<?php
require_once "vendor/econea/nusoap/src/nusoap.php";

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
    die("Error de conexión: " . $e->getMessage());
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

// Helper para validar si un token existe y es válido en la base de datos
function validate_token($token) {
    global $pdo;

    if (empty($token) || !is_string($token) || trim($token) === '' || !$pdo) {
        return false;
    }

    try {
        $stmt = $pdo->prepare("SELECT id, user_name FROM user WHERE token = :token AND token IS NOT NULL LIMIT 1");
        $cleanToken = trim($token);
        $stmt->bindParam(':token', $cleanToken);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        return $user ? true : false;
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
        'phone'       => array('name' => 'phone', 'type' => 'xsd:string'),
        'token'       => array('name' => 'token', 'type' => 'xsd:string')
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
        'phone'       => array('name' => 'phone', 'type' => 'xsd:string'),
        'token'       => array('name' => 'token', 'type' => 'xsd:string')
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

// 5.1 Servicio de Login y Generación de Token
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
    'Iniciar sesion y generar token con random_bytes'
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
    'Validar si un token es valido'
);

// 5.3 Operaciones CRUD protegidas con Token
$server->register(
    'InsertUserService',
    array(
        'data'  => 'tns:InsertUser',
        'token' => 'xsd:string'
    ),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Insertar un usuario (requiere token)'
);

$server->register(
    'UpdateUserService',
    array(
        'data'  => 'tns:UpdateUser',
        'token' => 'xsd:string'
    ),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Actualizar un usuario existente (requiere token)'
);

$server->register(
    'DeleteUserService',
    array(
        'id'    => 'xsd:int',
        'token' => 'xsd:string'
    ),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Eliminar un usuario por ID (requiere token)'
);

$server->register(
    'SelectUserService',
    array(
        'id'    => 'xsd:int',
        'token' => 'xsd:string'
    ),
    array('return' => 'tns:UserData'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Seleccionar un usuario por ID (requiere token)'
);

$server->register(
    'ListUsersService',
    array('token' => 'xsd:string'),
    array('return' => 'tns:UserArray'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Listar todos los usuarios (requiere token)'
);

// 6. Implementación de funciones del servicio

// 6.1 Iniciar sesión y Generar Token criptográficamente seguro
function LoginService($user_name, $password) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : "-1";
    }

    $user_name = trim(to_utf8($user_name));
    $password  = trim(to_utf8($password));

    if (empty($user_name) || empty($password)) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : "-1";
    }

    try {
        $stmt = $pdo->prepare("SELECT id, user_name, password FROM user WHERE user_name = :user_name LIMIT 1");
        $stmt->bindParam(':user_name', $user_name);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : "-1";
        }

        // Validación de contraseña encriptada
        if (!verify_password($password, $user['password'])) {
            return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : "-1";
        }

        // Generación del token seguro según especificación de clase:
        // RANDOM_BYTES() genera bytes criptográficamente seguros y BIN2HEX() los convierte a hexadecimal
        $token = bin2hex(random_bytes(32));

        // Guardar el token generado en la base de datos
        $updateStmt = $pdo->prepare("UPDATE user SET token = :token, token_date = NOW() WHERE id = :id");
        $updateStmt->bindParam(':token', $token);
        $updateStmt->bindParam(':id', $user['id']);
        $updateStmt->execute();

        return $token;

    } catch (PDOException $e) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : "-1";
    }
}

// 6.2 Validar Token
function ValidateTokenService($token) {
    if (validate_token($token)) {
        return "1";
    }
    return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : "-1";
}

// 6.3 Insertar usuario (Protegido por Token y con encriptación de contraseña)
function InsertUserService($data, $token = null) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    // Permitir token como parámetro independiente o dentro del arreglo $data
    $authToken = !empty($token) ? $token : ($data['token'] ?? null);
    if (!validate_token($authToken)) {
        return "-1";
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
        // Encriptar la contraseña usando algoritmo criptográfico seguro (bcrypt por defecto en PHP)
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

// 6.4 Actualizar usuario (Protegido por Token)
function UpdateUserService($data, $token = null) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    $authToken = !empty($token) ? $token : ($data['token'] ?? null);
    if (!validate_token($authToken)) {
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
        // Verificar existencia previa del usuario
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

// 6.5 Eliminar usuario (Protegido por Token)
function DeleteUserService($id, $token = null) {
    global $pdo;

    if (!$pdo) {
        return "-1";
    }

    if (is_array($id)) {
        $token = $token ?: ($id['token'] ?? null);
        $id = $id['id'] ?? null;
    }

    if (!validate_token($token)) {
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

// 6.6 Seleccionar usuario por ID (Protegido por Token)
function SelectUserService($id, $token = null) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    if (is_array($id)) {
        $token = $token ?: ($id['token'] ?? null);
        $id = $id['id'] ?? null;
    }

    if (!validate_token($token)) {
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

// 6.7 Listar todos los usuarios (Protegido por Token)
function ListUsersService($token = null) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    if (is_array($token)) {
        $token = $token['token'] ?? null;
    }

    if (!validate_token($token)) {
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
$POST_DATA = file_get_contents("php://input");
$server->service($POST_DATA);
exit();
