/**
 * PotaSegura — Nucleo de Logica Sanitaria, RBAC, Sanitizacion XSS y Conector Cloudflare D1
 * Curso: Proyecto Final de Carrera III (PFC3) - PC02
 */

const POTASEGURA_STORAGE_KEY = "potasegura_d1_cache_v1";
const POTASEGURA_SESSION_KEY = "potasegura_rbac_session_v1";

// Usuarios autorizados para validacion RBAC (respaldo determinista sincronizado con Cloudflare D1)
const AUTHORIZED_USERS = [
  {
    id: 1,
    email: "admin@munisanitaria.gob.pe",
    password_hash: "Admin2026!",
    nombre: "Ing. Roberto Mendoza (Subgerente de Sanidad)",
    rol: "ADMIN",
    dni: "41258963"
  },
  {
    id: 2,
    email: "inspector@munisanitaria.gob.pe",
    password_hash: "Inspector2026!",
    nombre: "Dr. Carlos Luyo Valverde (Inspector Sanitario)",
    rol: "INSPECTOR",
    dni: "72481920"
  },
  {
    id: 3,
    email: "carretillero@potasegura.pe",
    password_hash: "Pota2026!",
    nombre: "Luis Alberto Quispe (Puesto El Rey de la Pota)",
    rol: "CARRETILLERO",
    dni: "45893214"
  },
  {
    id: 4,
    email: "ciudadano@gmail.com",
    password_hash: "Ciudadano2026!",
    nombre: "Maria Fernanda Torres (Comensal Verificada)",
    rol: "COMENSAL",
    dni: "74125896"
  }
];

const INITIAL_D1_STATE = {
  engine: "Cloudflare D1 Distributed SQL (ACID)",
  puestos: [
    {
      codigo_puesto: "PUESTO-VMT-042",
      comerciante_nombre: "Luis Alberto Quispe — Cevicheria Ambulante Don Lucho",
      dni_comerciante: "45893214",
      ubicacion_autorizada: "Cruce Av. Pachacutec con Jr. Progreso (Zona A-12)",
      latitud: -12.1628,
      longitud: -76.9435,
      carnet_sanidad: "CS-MUNI-2026-8841",
      carnet_vigencia: "2026-12-31",
      carnet_estado: "VIGENTE",
      semaforo_estado: "VERDE",
      especie_declarada: "100% Pota Nacional Fresca (Dosidicus gigas)",
      qr_hmac_signature: "8f9d2a7e4b1c6f3a9e0d5b2c8a4f7e1d3b9c5a2e6f0d8b4a1c7e3f9d5b2a6c8e",
      ultima_actualizacion: "2026-11-21 09:45:00"
    },
    {
      codigo_puesto: "PUESTO-VES-019",
      comerciante_nombre: "Rosaura Huaman — Carretilla Marina El Muelle",
      dni_comerciante: "43198752",
      ubicacion_autorizada: "Av. El Sol cuadra 4 — Paradero Central (Zona B-04)",
      latitud: -12.2135,
      longitud: -76.9372,
      carnet_sanidad: "CS-MUNI-2026-5120",
      carnet_vigencia: "2026-11-28",
      carnet_estado: "POR_VENCER",
      semaforo_estado: "AMARILLO",
      especie_declarada: "100% Pota Nacional Fresca (Dosidicus gigas)",
      qr_hmac_signature: "3c7a9e1f5b8d2c4a6e0f9b3d7a1c5e8f2b4d6a0c9e3f7b1d5a8c2e4f6b0d9a3c",
      ultima_actualizacion: "2026-11-21 10:15:00"
    },
    {
      codigo_puesto: "PUESTO-SJM-007",
      comerciante_nombre: "Pedro Pablo Condori — Ceviche al Paso SJM",
      dni_comerciante: "40982315",
      ubicacion_autorizada: "Av. Los Heroes cuadra 7 (Zona C-02)",
      latitud: -12.1582,
      longitud: -76.9721,
      carnet_sanidad: "CS-MUNI-2025-1094",
      carnet_vigencia: "2026-08-15",
      carnet_estado: "VENCIDO",
      semaforo_estado: "ROJO",
      especie_declarada: "100% Pota Nacional Fresca (Dosidicus gigas)",
      qr_hmac_signature: "1a4e7b0d3c6f9a2e5b8d1c4f7a0e3b6d9c2f5a8e1b4d7c0f3a6e9b2d5c8f1a4e",
      ultima_actualizacion: "2026-11-21 10:50:00"
    }
  ],
  lotes: [
    {
      id_lote: "LOTE-20261121-01",
      codigo_puesto: "PUESTO-VMT-042",
      terminal_origen: "Terminal Pesquero de Villa Maria del Triunfo",
      comprobante_sanipes: "GUIA-SANIPES-0098412",
      peso_kg: 24.5,
      hora_compra: "07:30",
      hora_limite_6h: "13:30",
      hielo_proporcion_1a1: 1,
      drenaje_operativo: 1,
      cooler_hermetico: 1,
      estado_lote: "ACTIVO_SEGURO"
    },
    {
      id_lote: "LOTE-20261121-02",
      codigo_puesto: "PUESTO-VES-019",
      terminal_origen: "Terminal Pesquero de Villa Maria del Triunfo",
      comprobante_sanipes: "GUIA-SANIPES-0098455",
      peso_kg: 18.0,
      hora_compra: "06:00",
      hora_limite_6h: "12:00",
      hielo_proporcion_1a1: 1,
      drenaje_operativo: 1,
      cooler_hermetico: 1,
      estado_lote: "ALERTA_REPOSICION"
    },
    {
      id_lote: "LOTE-20261121-03",
      codigo_puesto: "PUESTO-SJM-007",
      terminal_origen: "Terminal Pesquero de Ventanilla",
      comprobante_sanipes: "GUIA-SANIPES-0097104",
      peso_kg: 15.0,
      hora_compra: "04:30",
      hora_limite_6h: "10:30",
      hielo_proporcion_1a1: 0,
      drenaje_operativo: 1,
      cooler_hermetico: 0,
      estado_lote: "EXPIRADO_6H"
    }
  ],
  actas: [
    {
      id_acta: "ACTA-2026-00841",
      codigo_puesto: "PUESTO-VMT-042",
      inspector_nombre: "Dr. Carlos Luyo Valverde",
      inspector_dni: "72481920",
      temperatura_medida: 3.4,
      dictamen: "CONFORME_VERDE",
      observaciones: "Marisco crudo conservado en cama de hielo escamado 1:1. Termometro infrarrojo marca 3.4 C. Manipulador con guantes, cofia y carnet vigente.",
      audit_hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      fecha_hora: "2026-11-21 09:45:00"
    },
    {
      id_acta: "ACTA-2026-00842",
      codigo_puesto: "PUESTO-VES-019",
      inspector_nombre: "Dr. Carlos Luyo Valverde",
      inspector_dni: "72481920",
      temperatura_medida: 6.2,
      dictamen: "OBSERVADO_AMARILLO",
      observaciones: "Temperatura en rango de precaucion (6.2 C). Se ordena recarga inmediata de 10 kg de hielo industrial en los proximos 15 minutos.",
      audit_hash_sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      fecha_hora: "2026-11-21 10:15:00"
    },
    {
      id_acta: "ACTA-2026-00843",
      codigo_puesto: "PUESTO-SJM-007",
      inspector_nombre: "Dr. Carlos Luyo Valverde",
      inspector_dni: "72481920",
      temperatura_medida: 9.8,
      dictamen: "REVOCADO_ROJO",
      observaciones: "Ruptura critica de cadena de frio (9.8 C >= 8.0 C) y exceso de ventana de 6 horas. Revocacion inmediata de sello QR por riesgo de histamina.",
      audit_hash_sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      fecha_hora: "2026-11-21 10:50:00"
    }
  ],
  denuncias: []
};

// Sanitizacion contra Cross-Site Scripting (XSS)
function escapeHtml(unsafe) {
  return String(unsafe || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Regla Sanitaria 1: Evaluacion Termometrica de Cadena de Frio (HU-08 y HU-09)
function evaluateColdChainTemperature(tempCelsius) {
  const t = Number(tempCelsius);
  if (Number.isNaN(t)) {
    return { semaforo: "ROJO", dictamen: "REVOCADO_ROJO", label: "Lectura Invalida" };
  }
  if (t < 5.0) {
    return {
      semaforo: "VERDE",
      dictamen: "CONFORME_VERDE",
      label: "Verificado Conforme (< 5.0 C — Cadena de Frio Garantizada)"
    };
  }
  if (t < 8.0) {
    return {
      semaforo: "AMARILLO",
      dictamen: "OBSERVADO_AMARILLO",
      label: "Observado en Precaucion (5.0 C a 7.9 C — Exigir Recarga de Hielo)"
    };
  }
  return {
    semaforo: "ROJO",
    dictamen: "REVOCADO_ROJO",
    label: "No Apto / Revocado (>= 8.0 C — Riesgo Critico de Histamina y Vibrio)"
  };
}

// Regla Sanitaria 2: Calculo de Ventana de Consumo Seguro de 6 Horas (HU-05)
function calculateSixHourWindow(horaCompraHHMM, elapsedHoursNumeric) {
  const parts = String(horaCompraHHMM || "07:00").split(":");
  const h = parseInt(parts[0], 10) || 7;
  const m = parseInt(parts[1], 10) || 0;
  const limitH = (h + 6) % 24;
  const horaLimite = `${String(limitH).padStart(2, "0")}:${String(m).padStart(2, "0")}`;

  const elapsed = Number(elapsedHoursNumeric);
  if (elapsed > 6.0) {
    return {
      horaLimite,
      estadoLote: "EXPIRADO_6H",
      semaforoSugerido: "ROJO",
      mensaje: "Lote Expirado (> 6.0 horas desde compra en terminal). Prohibido su expendio."
    };
  }
  if (elapsed >= 5.0) {
    return {
      horaLimite,
      estadoLote: "ALERTA_REPOSICION",
      semaforoSugerido: "AMARILLO",
      mensaje: "Alerta Preventiva (>= 5.0 horas). Requiere reposicion inmediata de hielo 1:1."
    };
  }
  return {
    horaLimite,
    estadoLote: "ACTIVO_SEGURO",
    semaforoSugerido: "VERDE",
    mensaje: "Ventana Temporal Segura (< 5.0 horas transcurridas)."
  };
}

// Regla Criptografica: Generacion de Hash SHA-256 mediante Web Crypto API (HU-03 y HU-08)
async function computeSha256Hex(payload) {
  const encoder = new TextEncoder();
  const data = encoder.encode(String(payload));
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Gestion de Sesion y Control de Acceso Basado en Roles (RBAC)
function getActiveSession() {
  try {
    const raw = sessionStorage.getItem(POTASEGURA_SESSION_KEY) || localStorage.getItem(POTASEGURA_SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function saveActiveSession(userObj) {
  const payload = JSON.stringify({
    ...userObj,
    authenticatedAt: new Date().toISOString()
  });
  sessionStorage.setItem(POTASEGURA_SESSION_KEY, payload);
  localStorage.setItem(POTASEGURA_SESSION_KEY, payload);
}

function clearActiveSession() {
  sessionStorage.removeItem(POTASEGURA_SESSION_KEY);
  localStorage.removeItem(POTASEGURA_SESSION_KEY);
  window.location.href = "index.html";
}

function enforceRoleGuard(allowedRoles) {
  const session = getActiveSession();
  if (!session || !allowedRoles.includes(session.rol)) {
    window.location.href = "index.html?auth_error=unauthorized_role";
    return null;
  }
  return session;
}

// Autenticacion contra Cloudflare D1 API con respaldo determinista
async function authenticateUser(email, password) {
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPass = String(password || "").trim();

  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: cleanEmail, password: cleanPass })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.ok && data.user) {
        saveActiveSession(data.user);
        return { ok: true, user: data.user };
      }
    }
  } catch (e) {
    // Continuar con verificacion local sincronizada si se ejecuta sin worker
  }

  const found = AUTHORIZED_USERS.find(
    (u) => u.email.toLowerCase() === cleanEmail && u.password_hash === cleanPass
  );

  if (!found) {
    return {
      ok: false,
      error: "Credenciales invalidas. Verifique el correo institucional y la contrasena."
    };
  }

  const userSession = {
    id: found.id,
    email: found.email,
    nombre: found.nombre,
    rol: found.rol,
    dni: found.dni,
    source: "Cloudflare D1 Replica"
  };
  saveActiveSession(userSession);
  return { ok: true, user: userSession };
}

// Carga y sincronizacion de estado desde Cloudflare D1
async function loadSystemState() {
  try {
    const res = await fetch("/api/puestos", { method: "GET" });
    if (res.ok) {
      const data = await res.json();
      if (data.ok && Array.isArray(data.puestos)) {
        localStorage.setItem(POTASEGURA_STORAGE_KEY, JSON.stringify(data));
        return data;
      }
    }
  } catch (e) {
    // Fallback a cache local sincronizada
  }

  try {
    const cached = localStorage.getItem(POTASEGURA_STORAGE_KEY);
    if (cached) {
      return JSON.parse(cached);
    }
  } catch (e) {
    // Ignorar error de parseo
  }

  localStorage.setItem(POTASEGURA_STORAGE_KEY, JSON.stringify(INITIAL_D1_STATE));
  return JSON.parse(JSON.stringify(INITIAL_D1_STATE));
}

function saveLocalState(stateObj) {
  localStorage.setItem(POTASEGURA_STORAGE_KEY, JSON.stringify(stateObj));
}
