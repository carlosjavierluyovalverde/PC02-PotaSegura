# PotaSegura — Plataforma Municipal de Trazabilidad, Cadena de Frio y Fiscalizacion Sanitaria

Sistema serverless distribuido en el borde (*Edge Computing*) para el control sanitario, empadronamiento municipal, custodia de cadena de frio ($< 5.0^\circ\text{C}$), regla temporal de consumo seguro ($T_{\text{limite}} = T_{\text{compra}} + 6\text{h}$) y transparencia ciudadana en la comercializacion ambulante de ceviche de pota (*Dosidicus gigas*).

## URL Publica Desplegada en la Nube

* **Produccion (Cloudflare Pages & Edge Workers):** https://potasegura.pages.dev

## Arquitectura de Seguridad y Separacion de Vistas (RBAC)

El sistema implementa aislamiento fisico de vistas HTML bajo el **Principio de Menor Privilegio**, evitando la exposicion de logica administrativa en interfaces publicas:

* `public/index.html`: Portal de autenticacion institucional RBAC y acceso directo de consulta ciudadana.
* `public/comerciante.html`: Modulo aislado para el comerciante carretillero (`CARRETILLERO`, `ADMIN`), protegido por verificacion de token firmado en el servidor (`/api/auth`).
* `public/inspector.html`: Modulo aislado para el inspector sanitario municipal (`INSPECTOR`, `ADMIN`), protegido por verificacion de token firmado en el servidor (`/api/auth`).
* `public/ciudadano.html`: Modulo publico sin requerimiento de descarga para comensales (`COMENSAL`) conectado exclusivamente al endpoint sanitizado `/api/publico`.

## Persistencia Relacional en Cloudflare D1

* **Motor:** Cloudflare D1 Distributed SQL (`potasegura-db`).
* **Esquema (`schema.sql`):** Tablas relacionales con integridad referencial (`usuarios`, `puestos`, `lotes_pota`, `actas_inspeccion`, `denuncias_ciudadanas`) y almacenamiento de hashes criptograficos SHA-256.
* **Seguridad de APIs:** Las rutas operativas (`/api/puestos`) exigen cabecera `Authorization: Bearer <token>` firmada criptograficamente y validan permisos por rol antes de ejecutar sentencias SQL parametrizadas.

## Ejecucion Local de Pruebas y Controles DevSecOps

```bash
npm ci
npm run build
python -m pytest -v tests/
python -m bandit -r src/
npm audit --audit-level=high
```
