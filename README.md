# PotaSegura — Plataforma Municipal de Trazabilidad, Cadena de Frio y Fiscalizacion Sanitaria

Sistema serverless distribuido en el borde (*Edge Computing*) para el control sanitario, empadronamiento municipal, custodia de cadena de frio ($< 5.0^\circ\text{C}$), regla temporal de consumo seguro ($T_{\text{limite}} = T_{\text{compra}} + 6\text{h}$) y transparencia ciudadana en la comercializacion ambulante de ceviche de pota (*Dosidicus gigas*).

## URL Publica Desplegada en la Nube

* **Produccion (Cloudflare Pages & Edge Workers):** https://potasegura.pages.dev

## Arquitectura de Seguridad y Separacion de Vistas (RBAC)

El sistema implementa aislamiento fisico de vistas HTML bajo el **Principio de Menor Privilegio**, evitando la exposicion de logica administrativa en interfaces publicas:

* `public/index.html`: Portal de autenticacion institucional RBAC y acceso directo de consulta ciudadana.
* `public/comerciante.html`: Modulo aislado para el comerciante carretillero (`CARRETILLERO`, `ADMIN`). Declaracion de lote SANIPES, calculo reactivo de ventana de 6 horas, checklist de cooler con hielo 1:1 y distintivo QR firmado con HMAC-SHA256.
* `public/inspector.html`: Modulo aislado para el inspector sanitario municipal (`INSPECTOR`, `ADMIN`). Verificacion de integridad criptografica de QR, termometria infrarroja in situ ($< 5.0^\circ\text{C}$ conforme, $\ge 8.0^\circ\text{C}$ revocacion automatica) y emision de actas digitales selladas con hash SHA-256 en Cloudflare D1.
* `public/ciudadano.html`: Modulo publico sin requerimiento de descarga para comensales (`COMENSAL`). Semaforo sanitario municipal en tiempo real, certificado de autenticidad **100% Pota Nacional Fresca** y buzon de denuncias con geocerca anti-sabotaje ($\le 50\text{ metros}$).

## Persistencia Relacional en Cloudflare D1

* **Motor:** Cloudflare D1 Distributed SQL (`potasegura-db`, ID: `f01f321d-25ff-4dae-a8dd-7c8ff029c57a`).
* **Esquema (`schema.sql`):** Tablas relacionales con integridad referencial (`usuarios`, `puestos`, `lotes_pota`, `actas_inspeccion`, `denuncias_ciudadanas`).
* **Seguridad SQL:** Consultas 100% parametrizadas en `functions/api/auth.js` y `functions/api/puestos.js` contra inyeccion SQL (SQLi).

## Credenciales Validas para Auditoria y Evaluacion

| Rol RBAC | Usuario / Correo | Contrasena | Modulo Autorizado |
| :--- | :--- | :--- | :--- |
| **CARRETILLERO** | `carretillero@potasegura.pe` | `Pota2026!` | `comerciante.html` |
| **INSPECTOR** | `inspector@munisanitaria.gob.pe` | `Inspector2026!` | `inspector.html` |
| **ADMIN** | `admin@munisanitaria.gob.pe` | `Admin2026!` | Acceso Total |
| **COMENSAL** | `ciudadano@gmail.com` | `Ciudadano2026!` | `ciudadano.html` (o acceso publico libre) |

## Ejecucion Local de Pruebas y Controles DevSecOps

```bash
# 1. Instalacion determinista de dependencias y verificacion de build
npm ci
npm run build

# 2. Ejecucion de pruebas unitarias automatizadas (Pytest)
python -m pytest -v tests/

# 3. Analisis Estatico de Seguridad SAST (Bandit) y Auditoria SCA (NPM Audit)
python -m bandit -r src/
npm audit --audit-level=high
```
