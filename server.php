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
$server->register(
    'InsertUserService',
    array('data' => 'tns:InsertUser'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Insertar un usuario'
);

$server->register(
    'UpdateUserService',
    array('data' => 'tns:UpdateUser'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Actualizar un usuario existente'
);

$server->register(
    'DeleteUserService',
    array('id' => 'xsd:int'),
    array('return' => 'xsd:string'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Eliminar un usuario por ID'
);

$server->register(
    'SelectUserService',
    array('id' => 'xsd:int'),
    array('return' => 'tns:UserData'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Seleccionar un usuario por ID'
);

$server->register(
    'ListUsersService',
    array(),
    array('return' => 'tns:UserArray'),
    $namespace,
    false,
    'rpc',
    'encoded',
    'Listar todos los usuarios'
);

// 6. Funciones del CRUD que procesan las peticiones y gestionan MySQL

// 6.1 Insertar usuario
function InsertUserService($data) {
    global $pdo;

    if (!$pdo) {
        return -1;
    }

    // Validación de campos requeridos
    if (
        empty($data['user_name']) || trim($data['user_name']) === '' ||
        empty($data['lastname']) || trim($data['lastname']) === '' ||
        !isset($data['doc_type_id']) || !is_numeric($data['doc_type_id']) || intval($data['doc_type_id']) <= 0 ||
        empty($data['num_doc']) || trim($data['num_doc']) === ''
    ) {
        return -1;
    }

    try {
        $sql = "INSERT INTO user (user_name, lastname, doc_type_id, num_doc, address, phone, created_date)
                VALUES (:user_name, :lastname, :doc_type_id, :num_doc, :address, :phone, NOW())";
        
        $stmt = $pdo->prepare($sql);
        $user_name   = to_utf8(trim($data['user_name']));
        $lastname    = to_utf8(trim($data['lastname']));
        $doc_type_id = intval($data['doc_type_id']);
        $num_doc     = to_utf8(trim($data['num_doc']));
        $address     = isset($data['address']) ? to_utf8(trim($data['address'])) : '';
        $phone       = isset($data['phone']) ? to_utf8(trim($data['phone'])) : '';

        $stmt->bindParam(':user_name', $user_name);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':doc_type_id', $doc_type_id);
        $stmt->bindParam(':num_doc', $num_doc);
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':phone', $phone);

        $stmt->execute();
        return "Se ha guardado correctamente";

    } catch (PDOException $e) {
        return -1;
    }
}

// 6.2 Actualizar usuario
function UpdateUserService($data) {
    global $pdo;

    if (!$pdo) {
        return -1;
    }

    // Validación de ID
    if (empty($data['id']) || !is_numeric($data['id']) || intval($data['id']) <= 0) {
        return -1;
    }

    // Validación de campos requeridos
    if (
        empty($data['user_name']) || trim($data['user_name']) === '' ||
        empty($data['lastname']) || trim($data['lastname']) === '' ||
        !isset($data['doc_type_id']) || !is_numeric($data['doc_type_id']) || intval($data['doc_type_id']) <= 0 ||
        empty($data['num_doc']) || trim($data['num_doc']) === ''
    ) {
        return -1;
    }

    try {
        // Verificar existencia previa del usuario
        $check = $pdo->prepare("SELECT id FROM user WHERE id = :id");
        $check->execute(array(':id' => intval($data['id'])));
        if ($check->rowCount() === 0) {
            return -1;
        }

        $sql = "UPDATE user SET 
                    user_name = :user_name,
                    lastname = :lastname,
                    doc_type_id = :doc_type_id,
                    num_doc = :num_doc,
                    address = :address,
                    phone = :phone
                WHERE id = :id";
        
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
        $stmt->bindParam(':address', $address);
        $stmt->bindParam(':phone', $phone);

        $stmt->execute();
        return "Usuario actualizado correctamente";

    } catch (PDOException $e) {
        return -1;
    }
}

// 6.3 Eliminar usuario
function DeleteUserService($id) {
    global $pdo;

    if (!$pdo) {
        return -1;
    }

    if (is_array($id)) {
        $id = $id['id'] ?? null;
    }

    // Validación de ID
    if (empty($id) || !is_numeric($id) || intval($id) <= 0) {
        return -1;
    }

    try {
        // Verificar existencia previa del usuario
        $check = $pdo->prepare("SELECT id FROM user WHERE id = :id");
        $check->execute(array(':id' => intval($id)));
        if ($check->rowCount() === 0) {
            return -1;
        }

        $stmt = $pdo->prepare("DELETE FROM user WHERE id = :id");
        $userId = intval($id);
        $stmt->bindParam(':id', $userId);
        $stmt->execute();

        return "Usuario eliminado correctamente";

    } catch (PDOException $e) {
        return -1;
    }
}

// 6.4 Seleccionar usuario por ID
function SelectUserService($id) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    if (is_array($id)) {
        $id = $id['id'] ?? null;
    }

    // Validación de ID
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

// 6.5 Listar todos los usuarios
function ListUsersService($param = null) {
    global $pdo;

    if (!$pdo) {
        return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
    }

    try {
        $stmt = $pdo->query("SELECT id, user_name, lastname, doc_type_id, num_doc, address, phone, created_date FROM user ORDER BY id ASC");
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($users)) {
            return class_exists('soapval') ? new soapval('return', 'xsd:string', '-1') : -1;
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
