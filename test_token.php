<?php
/**
 * ==========================================================
 * SUITE DE PRUEBAS AUTOMATIZADA: TOKEN CRIPTOGRÁFICO & WS-SECURITY
 * ARCHIVO: test_token.php
 * DESCRIPCIÓN: Verifica de forma integral y reproducible:
 *   1. Generación de tokens criptográficos con random_bytes(32) -> 64 hex.
 *   2. Verificación dual de contraseñas (Bcrypt nativo y SHA-256 de MySQL).
 *   3. Extracción de cabecera WS-Security (<wsse:Security><wsse:UsernameToken>).
 *   4. Validación de seguridad con y sin base de datos.
 * ==========================================================
 */

if (!isset($_SERVER['SERVER_NAME'])) {
    $_SERVER['SERVER_NAME'] = 'localhost';
}

define('TESTING_MODE', true);
require_once __DIR__ . '/server.php';

echo "==========================================================\n";
echo " INICIANDO SUITE DE PRUEBAS: FASE TOKEN & WS-SECURITY\n";
echo "==========================================================\n\n";

$passed = 0;
$total = 0;

function assertTest($description, $condition) {
    global $passed, $total;
    $total++;
    if ($condition) {
        $passed++;
        echo " [OK] " . $description . "\n";
    } else {
        echo " [FALLO] " . $description . "\n";
    }
}

// ----------------------------------------------------------
// PRUEBA 1: Generación de Tokens Criptográficos
// ----------------------------------------------------------
$token1 = bin2hex(random_bytes(32));
$token2 = bin2hex(random_bytes(32));

assertTest("Token 1 tiene longitud exacta de 64 caracteres hexadecimales", strlen($token1) === 64 && ctype_xdigit($token1));
assertTest("Token 2 tiene longitud exacta de 64 caracteres hexadecimales", strlen($token2) === 64 && ctype_xdigit($token2));
assertTest("Los tokens generados son únicos y criptográficamente aleatorios", $token1 !== $token2);

// ----------------------------------------------------------
// PRUEBA 2: Soporte de Contraseñas (Bcrypt y SHA-256)
// ----------------------------------------------------------
$rawPasswordBcrypt = "admin123";
$bcryptHash = password_hash($rawPasswordBcrypt, PASSWORD_DEFAULT);

$rawPasswordSha = "operador123";
$mysqlSha256Hash = hash('sha256', $rawPasswordSha);

assertTest("Verificación exitosa con hash nativo PHP (Bcrypt / password_verify)", verify_password($rawPasswordBcrypt, $bcryptHash));
assertTest("Verificación exitosa con hash SHA-256 de MySQL (SHA2)", verify_password($rawPasswordSha, $mysqlSha256Hash));
assertTest("Rechazo ante contraseña incorrecta en Bcrypt", !verify_password("clave_erronea", $bcryptHash));
assertTest("Rechazo ante contraseña incorrecta en SHA-256", !verify_password("clave_erronea", $mysqlSha256Hash));

// ----------------------------------------------------------
// PRUEBA 3: Extracción de Cabecera WS-Security (<soap:Header>)
// ----------------------------------------------------------
$validSoapXml = <<<XML
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                  xmlns:ins="InsertUserSOAP">
   <soapenv:Header>
      <wsse:Security>
         <wsse:UsernameToken>
            <wsse:Username>admin</wsse:Username>
            <wsse:Password>$token1</wsse:Password>
         </wsse:UsernameToken>
      </wsse:Security>
   </soapenv:Header>
   <soapenv:Body>
      <ins:SelectUserService>
         <id>1</id>
      </ins:SelectUserService>
   </soapenv:Body>
</soapenv:Envelope>
XML;

$GLOBALS['RAW_POST_DATA'] = $validSoapXml;
$POST_DATA = $validSoapXml;
$extracted = get_ws_security_header();

assertTest("Extracción de Username desde <wsse:Security><wsse:UsernameToken>", isset($extracted['username']) && $extracted['username'] === 'admin');
assertTest("Extracción de Password/Token desde <wsse:Security><wsse:UsernameToken>", isset($extracted['password']) && $extracted['password'] === $token1);

$noHeaderSoapXml = <<<XML
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ins="InsertUserSOAP">
   <soapenv:Body>
      <ins:SelectUserService>
         <id>1</id>
      </ins:SelectUserService>
   </soapenv:Body>
</soapenv:Envelope>
XML;

$GLOBALS['RAW_POST_DATA'] = $noHeaderSoapXml;
$POST_DATA = $noHeaderSoapXml;
$extractedNoHeader = get_ws_security_header();

assertTest("Detección de ausencia de credenciales WS-Security", empty($extractedNoHeader['username']) && empty($extractedNoHeader['password']) && empty($extractedNoHeader['token']));

// ----------------------------------------------------------
// PRUEBA 4: Comprobación de Servicios con Base de Datos (MySQL)
// ----------------------------------------------------------
if ($pdo) {
    echo "\n--- Probando servicios contra MySQL (soap_cptec) ---\n";

    // 4.1 LoginService con usuario semilla 'admin' (si existe)
    $loginResult = LoginService('admin', 'admin123');
    if ($loginResult !== "-1") {
        assertTest("LoginService retorna token de 64 hex con credenciales válidas", strlen($loginResult) === 64 && ctype_xdigit($loginResult));
        $validToken = ValidateTokenService($loginResult);
        assertTest("ValidateTokenService con token activo retorna 1", $validToken === "1");
    } else {
        echo " [INFO] Usuario semilla 'admin' no encontrado en BD para prueba de Login.\n";
    }

    // 4.2 LoginService con contraseña errónea
    $failedLogin = LoginService('admin', 'clave_incorrecta_xyz_999');
    assertTest("LoginService con contraseña inválida retorna -1", $failedLogin === "-1" || (is_object($failedLogin) && $failedLogin->getval() === '-1'));

} else {
    echo "\n [INFO] MySQL no disponible en este entorno o la base de datos 'soap_cptec' no está inicializada.\n";
}

// ----------------------------------------------------------
// RESUMEN
// ----------------------------------------------------------
echo "\n==========================================================\n";
echo " RESUMEN: $passed / $total pruebas pasadas exitosamente.\n";
echo "==========================================================\n";

if ($passed === $total) {
    exit(0);
} else {
    exit(1);
}
