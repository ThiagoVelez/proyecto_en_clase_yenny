# Proyecto en Clase Yenny - Servicio Web SOAP (PHP & MySQL)

Servicio web SOAP implementado en PHP utilizando la librería **NuSOAP** y conexión a base de datos MySQL mediante **PDO**.

##  Descripción

Este proyecto expone un servidor SOAP con WSDL que permite realizar operaciones CRUD sobre la tabla `user`:
- `InsertUserService`: Registra un nuevo usuario con validación de datos requeridos y unicidad de documento.
- `UpdateUserService`: Modifica la información de un usuario existente.
- `DeleteUserService`: Elimina un usuario por su ID.
- `SelectUserService`: Obtiene los datos detallados de un usuario específico.
- `ListUsersService`: Lista todos los usuarios registrados.

##  Estructura del Proyecto

```text
├── composer.json           # Definición de dependencias (econea/nusoap)
├── composer.lock           # Bloqueo de versiones instaladas
├── database/
│   └── soap_cptec.sql      # Script de base de datos MySQL (tablas doc_type y user)
├── server.php              # Servidor SOAP y lógica de negocio
└── vendor/                 # Dependencias instaladas (NuSOAP)
```

##  Requisitos

- Servidor web Apache con PHP (v7.4 o superior recomendado, e.g., XAMPP, WAMP, Laragon).
- Servidor de base de datos MySQL / MariaDB.
- Extensiones PHP activas: `pdo_mysql`, `mbstring`.

##  Puesta en Marcha

1. **Importar la Base de Datos**:
   - Abrir phpMyAdmin o su gestor MySQL preferido.
   - Crear o importar el script ubicado en `database/soap_cptec.sql`.

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
     http://localhost/ruta-del-proyecto/server.php?wsdl
     ```
