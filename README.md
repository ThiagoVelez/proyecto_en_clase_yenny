# Proyecto en Clase Yenny - Servicio Web SOAP (PHP & MySQL)

Servicio web SOAP implementado en PHP utilizando la librería **NuSOAP**, conexión a base de datos MySQL mediante **PDO**, contraseñas encriptadas y seguridad mediante **WS-Security (`<soap:Header>`)** y tokens criptográficos.

## Descripción

Este proyecto expone un servidor SOAP con WSDL protegido con el estándar **WS-Security** en el `<soap:Header>` y operaciones sobre la tabla `user`:

### Operaciones de Autenticación y Token
- `LoginService`: Recibe `user_name` y `password`, valida la contraseña encriptada y genera un token criptográfico seguro utilizando `$token = bin2hex(random_bytes(32));` que se almacena en la base de datos.
- `ValidateTokenService`: Valida la autenticidad y existencia de un token en la base de datos.

### Operaciones CRUD (Protegidas con WS-Security en el Header)
- `InsertUserService`: Registra un nuevo usuario encriptando la contraseña con `password_hash`.
- `UpdateUserService`: Modifica la información de un usuario existente.
- `DeleteUserService`: Elimina un usuario por su ID.
- `SelectUserService`: Obtiene los datos detallados de un usuario específico sin exponer contraseñas.
- `ListUsersService`: Lista todos los usuarios registrados sin exponer contraseñas.

## WS-Security en el Header (Especificación de la Diapositiva)

Tal como se indicó en clase, la seguridad se incorpora dentro del elemento `<soap:Header>` mediante el estándar **WS-Security** (`wsse:Security` y `wsse:UsernameToken`).

### Formato XML de Petición (SoapUI / Postman):
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:ins="InsertUserSOAP">
   <soapenv:Header>
      <wsse:Security>
         <wsse:UsernameToken>
            <wsse:Username>admin</wsse:Username>
            <wsse:Password>123456</wsse:Password>
         </wsse:UsernameToken>
      </wsse:Security>
   </soapenv:Header>
   <soapenv:Body>
      <ins:ListUsersService/>
   </soapenv:Body>
</soapenv:Envelope>
```

*Nota: También es posible enviar en `<wsse:Password>` el token generado con `LoginService` o usar la etiqueta directa `<token>tu_token</token>` en la cabecera.*

## Generación del Token y Encriptación

### Generación del Token
Se utiliza la función criptográficamente segura `random_bytes()` y se convierte a cadena hexadecimal legible mediante `bin2hex()`:
```php
$token = bin2hex(random_bytes(32));
```

### Encriptación de Contraseñas
- **Base de Datos (`database/soap_cptec.sql`)**: Las contraseñas se almacenan encriptadas con hashes criptográficos (soporta hashes SHA-256 generados mediante `SHA2('password', 256)` y hashes nativos de PHP).
- **PHP (`server.php`)**: Al insertar o actualizar usuarios, la contraseña se hashea con `password_hash($password, PASSWORD_DEFAULT)`.

## Estructura del Proyecto

```text
├── composer.json           # Definición de dependencias (econea/nusoap)
├── composer.lock           # Bloqueo de versiones instaladas
├── database/
│   └── soap_cptec.sql      # Script de base de datos MySQL con contraseñas encriptadas
├── server.php              # Servidor SOAP con soporte completo WS-Security y CRUD
└── vendor/                 # Dependencias instaladas (NuSOAP)
```

## Requisitos

- Servidor web Apache con PHP (v7.4 o superior recomendado, e.g., XAMPP, WAMP, Laragon).
- Servidor de base de datos MySQL / MariaDB.
- Extensiones PHP activas: `pdo_mysql`, `mbstring`, `openssl`.

## Puesta en Marcha

1. **Importar la Base de Datos**:
   - Abrir phpMyAdmin o su gestor MySQL preferido.
   - Crear o importar el script ubicado en `database/soap_cptec.sql`.
   - Usuarios de prueba con contraseñas encriptadas:
     - Usuario: `admin` | Contraseña: `123456`
     - Usuario: `yenny_docente` | Contraseña: `123456`
     - Usuario: `santiago` | Contraseña: `123456`

2. **Configuración de Conexión**:
   - En `server.php`, verificar los parámetros de conexión según el entorno local:
     ```php
     $host = "127.0.0.1";
     $port = "3306";
     $dbname = "soap_cptec";
     $username = "root";
     $password = "";
     ```

3. **Acceso al WSDL**:
   - Acceder al servicio desde el navegador o cliente SOAP (Postman / SoapUI):
     ```text
     http://localhost:8000/server.php?wsdl
     ```
