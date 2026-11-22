const POTASEGURA_SESSION_KEY = "potasegura_rbac_session_v2";
const POTASEGURA_TOKEN_KEY = "potasegura_rbac_token_v2";

function escapeHtml(unsafe) {
  return String(unsafe || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

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

async function computeSha256Hex(payload) {
  const encoder = new TextEncoder();
  const data = encoder.encode(String(payload));
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getSessionToken() {
  return sessionStorage.getItem(POTASEGURA_TOKEN_KEY) || "";
}

function getActiveSession() {
  try {
    const raw = sessionStorage.getItem(POTASEGURA_SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function saveActiveSession(userObj, tokenStr) {
  sessionStorage.setItem(POTASEGURA_SESSION_KEY, JSON.stringify(userObj));
  sessionStorage.setItem(POTASEGURA_TOKEN_KEY, String(tokenStr || ""));
}

function clearActiveSession() {
  sessionStorage.removeItem(POTASEGURA_SESSION_KEY);
  sessionStorage.removeItem(POTASEGURA_TOKEN_KEY);
  window.location.href = "index.html";
}

async function enforceRoleGuard(allowedRoles) {
  const token = getSessionToken();
  const localUser = getActiveSession();
  if (!token || !localUser || !allowedRoles.includes(localUser.rol)) {
    window.location.href = "index.html?auth_error=unauthorized_role";
    return null;
  }

  try {
    const res = await fetch("/api/auth", {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) {
      clearActiveSession();
      return null;
    }
    const data = await res.json();
    if (!data.ok || !data.user || !allowedRoles.includes(data.user.rol)) {
      window.location.href = "index.html?auth_error=unauthorized_role";
      return null;
    }
    return data.user;
  } catch (err) {
    window.location.href = "index.html?auth_error=unauthorized_role";
    return null;
  }
}

async function authenticateUser(email, password) {
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPass = String(password || "").trim();

  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: cleanEmail, password: cleanPass })
    });
    const data = await res.json();
    if (res.ok && data.ok && data.user && data.session_token) {
      saveActiveSession(data.user, data.session_token);
      return { ok: true, user: data.user };
    }
    return {
      ok: false,
      error: data.error || "Credenciales invalidas o usuario no autorizado.",
      bloqueado: Boolean(data.bloqueado),
      segundos_restantes: Number(data.segundos_restantes || 0),
      intentos: Number(data.intentos || 0),
      max_intentos: Number(data.max_intentos || 5)
    };
  } catch (e) {
    return {
      ok: false,
      error: "No se pudo conectar con el servicio de autenticacion en el borde.",
      bloqueado: false,
      segundos_restantes: 0
    };
  }
}

async function loadSystemState() {
  const token = getSessionToken();
  const res = await fetch("/api/puestos", {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) {
    throw new Error("Sesion no autorizada para consultar registros internos.");
  }
  return await res.json();
}

async function submitAuthorizedTransaction(payload) {
  const token = getSessionToken();
  const res = await fetch("/api/puestos", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify(payload)
  });
  return await res.json();
}

async function loadPublicPuesto(codigoPuesto) {
  const res = await fetch(`/api/publico?puesto=${encodeURIComponent(codigoPuesto)}`, {
    method: "GET"
  });
  return await res.json();
}

async function submitPublicDenuncia(payload) {
  const res = await fetch("/api/publico", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  return { ok: res.ok && data.ok, ...data };
}
