# Proyecto en Clase Yenny - Servicio Web SOAP (PHP & MySQL)

Servicio web SOAP implementado en PHP utilizando la librería **NuSOAP**, conexión a base de datos MySQL mediante **PDO**, sistema de contraseñas encriptadas y autenticación mediante tokens criptográficos.

## Descripción

Este proyecto expone un servidor SOAP con WSDL que implementa autenticación por tokens y operaciones CRUD protegidas sobre la tabla `user`:

### Operaciones de Autenticación y Token
- `LoginService`: Recibe `user_name` y `password`, valida la contraseña encriptada y genera un token criptográfico seguro utilizando `$token = bin2hex(random_bytes(32));` que se almacena en la base de datos.
- `ValidateTokenService`: Valida la autenticidad y existencia de un token en la base de datos.

### Operaciones CRUD (Protegidas con Token)
- `InsertUserService`: Registra un nuevo usuario encriptando la contraseña con algoritmo hash seguro (`password_hash`) y validando el token de autorización.
- `UpdateUserService`: Modifica la información de un usuario existente (requiere token).
- `DeleteUserService`: Elimina un usuario por su ID (requiere token).
- `SelectUserService`: Obtiene los datos detallados de un usuario específico sin exponer contraseñas (requiere token).
- `ListUsersService`: Lista todos los usuarios registrados sin exponer contraseñas (requiere token).

## Generación del Token y Encriptación

### Generación del Token (especificación de clase)
Se utiliza la función criptográficamente segura `random_bytes()` y se convierte a cadena hexadecimal legible mediante `bin2hex()`:
```php
$token = bin2hex(random_bytes(32));
```

### Encriptación de Contraseñas
- **Base de Datos (`database/soap_cptec.sql`)**: Las contraseñas de los usuarios se almacenan encriptadas (soporta hashes SHA-256 generados mediante `SHA2('password', 256)` y hashes nativos de PHP).
- **PHP (`server.php`)**: Al crear o actualizar usuarios, la contraseña se hashea con `password_hash($password, PASSWORD_DEFAULT)`. La verificación se realiza de manera segura con `password_verify()` y validación contra hashes SHA-256.

## Estructura del Proyecto

```text
├── composer.json           # Definición de dependencias (econea/nusoap)
├── composer.lock           # Bloqueo de versiones instaladas
├── database/
│   └── soap_cptec.sql      # Script de base de datos MySQL con contraseñas encriptadas
├── server.php              # Servidor SOAP, autenticación, tokens y CRUD
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
   - Incluye usuarios de prueba con contraseñas encriptadas:
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
