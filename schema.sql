DROP TABLE IF EXISTS denuncias_ciudadanas;
DROP TABLE IF EXISTS actas_inspeccion;
DROP TABLE IF EXISTS lotes_pota;
DROP TABLE IF EXISTS puestos;
DROP TABLE IF EXISTS usuarios;

CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nombre TEXT NOT NULL,
    rol TEXT NOT NULL CHECK(rol IN ('ADMIN', 'INSPECTOR', 'CARRETILLERO', 'COMENSAL')),
    dni TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE puestos (
    codigo_puesto TEXT PRIMARY KEY,
    comerciante_nombre TEXT NOT NULL,
    dni_comerciante TEXT NOT NULL,
    ubicacion_autorizada TEXT NOT NULL,
    latitud REAL NOT NULL,
    longitud REAL NOT NULL,
    carnet_sanidad TEXT NOT NULL,
    carnet_vigencia DATE NOT NULL,
    carnet_estado TEXT NOT NULL CHECK(carnet_estado IN ('VIGENTE', 'POR_VENCER', 'VENCIDO')),
    semaforo_estado TEXT NOT NULL CHECK(semaforo_estado IN ('VERDE', 'AMARILLO', 'ROJO')),
    especie_declarada TEXT NOT NULL DEFAULT '100% Pota Nacional Fresca (Dosidicus gigas)',
    qr_hmac_signature TEXT NOT NULL,
    ultima_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lotes_pota (
    id_lote TEXT PRIMARY KEY,
    codigo_puesto TEXT NOT NULL,
    terminal_origen TEXT NOT NULL,
    comprobante_sanipes TEXT NOT NULL,
    peso_kg REAL NOT NULL,
    hora_compra TEXT NOT NULL,
    hora_limite_6h TEXT NOT NULL,
    hielo_proporcion_1a1 INTEGER NOT NULL DEFAULT 1,
    drenaje_operativo INTEGER NOT NULL DEFAULT 1,
    cooler_hermetico INTEGER NOT NULL DEFAULT 1,
    estado_lote TEXT NOT NULL CHECK(estado_lote IN ('ACTIVO_SEGURO', 'ALERTA_REPOSICION', 'EXPIRADO_6H')),
    FOREIGN KEY (codigo_puesto) REFERENCES puestos(codigo_puesto)
);

CREATE TABLE actas_inspeccion (
    id_acta TEXT PRIMARY KEY,
    codigo_puesto TEXT NOT NULL,
    inspector_nombre TEXT NOT NULL,
    inspector_dni TEXT NOT NULL,
    temperatura_medida REAL NOT NULL,
    dictamen TEXT NOT NULL CHECK(dictamen IN ('CONFORME_VERDE', 'OBSERVADO_AMARILLO', 'REVOCADO_ROJO')),
    observaciones TEXT NOT NULL,
    audit_hash_sha256 TEXT NOT NULL,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codigo_puesto) REFERENCES puestos(codigo_puesto)
);

CREATE TABLE denuncias_ciudadanas (
    id_denuncia INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_puesto TEXT NOT NULL,
    motivo TEXT NOT NULL,
    comentario TEXT NOT NULL,
    distancia_metros REAL NOT NULL,
    geocerca_valida INTEGER NOT NULL CHECK(geocerca_valida IN (0, 1)),
    fecha_reporte DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codigo_puesto) REFERENCES puestos(codigo_puesto)
);

INSERT INTO usuarios (email, password_hash, nombre, rol, dni) VALUES
('admin@munisanitaria.gob.pe', '04445e6487736590d1ef50186b414e737e0164683cbbec64e00e73c000fd3bef', 'Ing. Roberto Mendoza (Subgerente de Sanidad)', 'ADMIN', '41258963'),
('inspector@munisanitaria.gob.pe', '0b98b16c6327e921b1d7042d586d60c2475547a789038ebc0646d69e5074f68a', 'Dr. Carlos Luyo Valverde (Inspector Sanitario)', 'INSPECTOR', '72481920'),
('carretillero@potasegura.pe', 'b07c1c70796e3722f8db0abb9f64c1a1e7a91124abe03a8ea51a17818ce2d79c', 'Luis Alberto Quispe (Puesto El Rey de la Pota)', 'CARRETILLERO', '45893214'),
('ciudadano@gmail.com', '00c79ac618f6cc8b30882bb2eb09e573e7f1219c991690656f0abd85d0b77299', 'Maria Fernanda Torres (Comensal Verificada)', 'COMENSAL', '74125896');

INSERT INTO puestos (codigo_puesto, comerciante_nombre, dni_comerciante, ubicacion_autorizada, latitud, longitud, carnet_sanidad, carnet_vigencia, carnet_estado, semaforo_estado, especie_declarada, qr_hmac_signature) VALUES
('PUESTO-VMT-042', 'Luis Alberto Quispe — Cevicheria Ambulante Don Lucho', '45893214', 'Cruce Av. Pachacutec con Jr. Progreso (Zona A-12)', -12.1628, -76.9435, 'CS-MUNI-2026-8841', '2026-12-31', 'VIGENTE', 'VERDE', '100% Pota Nacional Fresca (Dosidicus gigas)', '8f9d2a7e4b1c6f3a9e0d5b2c8a4f7e1d3b9c5a2e6f0d8b4a1c7e3f9d5b2a6c8e'),
('PUESTO-VES-019', 'Rosaura Huaman — Carretilla Marina El Muelle', '43198752', 'Av. El Sol cuadra 4 — Paradero Central (Zona B-04)', -12.2135, -76.9372, 'CS-MUNI-2026-5120', '2026-11-28', 'POR_VENCER', 'AMARILLO', '100% Pota Nacional Fresca (Dosidicus gigas)', '3c7a9e1f5b8d2c4a6e0f9b3d7a1c5e8f2b4d6a0c9e3f7b1d5a8c2e4f6b0d9a3c'),
('PUESTO-SJM-007', 'Pedro Pablo Condori — Ceviche al Paso SJM', '40982315', 'Av. Los Heroes cuadra 7 (Zona C-02)', -12.1582, -76.9721, 'CS-MUNI-2025-1094', '2026-08-15', 'VENCIDO', 'ROJO', '100% Pota Nacional Fresca (Dosidicus gigas)', '1a4e7b0d3c6f9a2e5b8d1c4f7a0e3b6d9c2f5a8e1b4d7c0f3a6e9b2d5c8f1a4e');

INSERT INTO lotes_pota (id_lote, codigo_puesto, terminal_origen, comprobante_sanipes, peso_kg, hora_compra, hora_limite_6h, hielo_proporcion_1a1, drenaje_operativo, cooler_hermetico, estado_lote) VALUES
('LOTE-20261121-01', 'PUESTO-VMT-042', 'Terminal Pesquero de Villa Maria del Triunfo', 'GUIA-SANIPES-0098412', 24.5, '07:30', '13:30', 1, 1, 1, 'ACTIVO_SEGURO'),
('LOTE-20261121-02', 'PUESTO-VES-019', 'Terminal Pesquero de Villa Maria del Triunfo', 'GUIA-SANIPES-0098455', 18.0, '06:00', '12:00', 1, 1, 1, 'ALERTA_REPOSICION'),
('LOTE-20261121-03', 'PUESTO-SJM-007', 'Terminal Pesquero de Ventanilla', 'GUIA-SANIPES-0097104', 15.0, '04:30', '10:30', 0, 1, 0, 'EXPIRADO_6H');

INSERT INTO actas_inspeccion (id_acta, codigo_puesto, inspector_nombre, inspector_dni, temperatura_medida, dictamen, observaciones, audit_hash_sha256, fecha_hora) VALUES
('ACTA-2026-00841', 'PUESTO-VMT-042', 'Dr. Carlos Luyo Valverde', '72481920', 3.4, 'CONFORME_VERDE', 'Marisco crudo conservado en cama de hielo escamado 1:1. Termometro infrarrojo marca 3.4 C. Manipulador con guantes, cofia y carnet vigente.', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '2026-11-21 09:45:00'),
('ACTA-2026-00842', 'PUESTO-VES-019', 'Dr. Carlos Luyo Valverde', '72481920', 6.2, 'OBSERVADO_AMARILLO', 'Temperatura en rango de precaucion (6.2 C). Se ordena recarga inmediata de 10 kg de hielo industrial en los proximos 15 minutos.', '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4', '2026-11-21 10:15:00'),
('ACTA-2026-00843', 'PUESTO-SJM-007', 'Dr. Carlos Luyo Valverde', '72481920', 9.8, 'REVOCADO_ROJO', 'Ruptura critica de cadena de frio (9.8 C >= 8.0 C) y exceso de ventana de 6 horas. Revocacion inmediata de sello QR por riesgo de histamina.', '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', '2026-11-21 10:50:00');
