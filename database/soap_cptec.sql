-- =====================================================
-- Script de Creación de Base de Datos para Servicio SOAP
-- Base de Datos: soap_cptec
-- =====================================================

-- 1. Creación de la base de datos si no existe
CREATE DATABASE IF NOT EXISTS `soap_cptec` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `soap_cptec`;

-- 2. Creación de tabla para Tipos de Documento
CREATE TABLE IF NOT EXISTS `document_type` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `code` VARCHAR(10) NOT NULL UNIQUE COMMENT 'Ej: CC, TI, CE, PAS, NIT',
    `name` VARCHAR(100) NOT NULL COMMENT 'Nombre descriptivo del tipo de documento'
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- 3. Inserción de tipos de documentos comunes (usando alias moderno compatible con MySQL 8+)
INSERT INTO
    `document_type` (`id`, `code`, `name`)
VALUES (
        1,
        'CC',
        'Cédula de Ciudadanía'
    ),
    (
        2,
        'TI',
        'Tarjeta de Identidad'
    ),
    (
        3,
        'CE',
        'Cédula de Extranjería'
    ),
    (4, 'PAS', 'Pasaporte'),
    (
        5,
        'NIT',
        'Número de Identificación Tributaria'
    ) AS new_dt
ON DUPLICATE KEY UPDATE
    `name` = new_dt.name;

-- 4. Creación de tabla 'user' compatible con autenticación y tokens
CREATE TABLE IF NOT EXISTS `user` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_name` VARCHAR(100) NOT NULL COMMENT 'Nombre del usuario / username para login',
    `lastname` VARCHAR(100) NOT NULL COMMENT 'Apellido del usuario',
    `doc_type_id` INT NOT NULL COMMENT 'ID del tipo de documento',
    `num_doc` VARCHAR(50) NOT NULL COMMENT 'Número de documento',
    `password` VARCHAR(255) NOT NULL COMMENT 'Contraseña encriptada/hasheada',
    `token` VARCHAR(64) DEFAULT NULL COMMENT 'Token criptográfico generado con bin2hex(random_bytes(32))',
    `token_date` DATETIME DEFAULT NULL COMMENT 'Fecha y hora de generación del token',
    `address` VARCHAR(255) DEFAULT NULL COMMENT 'Dirección de residencia',
    `phone` VARCHAR(30) DEFAULT NULL COMMENT 'Número de teléfono/contacto',
    `created_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Fecha de registro',
    CONSTRAINT `fk_user_doc_type` FOREIGN KEY (`doc_type_id`) REFERENCES `document_type` (`id`) ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;