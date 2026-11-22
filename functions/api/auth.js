async function sha256Hex(input) {
  const data = new TextEncoder().encode(String(input));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function signPayload(payloadStr, env) {
  const seed = String((env && env.SESSION_SIGNING_SEED) || "potasegura-edge-rbac-v1");
  return sha256Hex(`${payloadStr}.${seed}`);
}

export async function verifyBearerToken(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }
  const rawToken = authHeader.slice(7).trim();
  const parts = rawToken.split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [b64Payload, signature] = parts;
  const expectedSig = await signPayload(b64Payload, env);
  if (signature !== expectedSig) {
    return null;
  }
  try {
    const decoded = JSON.parse(atob(b64Payload));
    if (!decoded.exp || Date.now() > decoded.exp) {
      return null;
    }
    return decoded;
  } catch (err) {
    return null;
  }
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const session = await verifyBearerToken(request, env);
  if (!session) {
    return new Response(
      JSON.stringify({ ok: false, error: "Sesion no valida o expirada." }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }
  return new Response(
    JSON.stringify({ ok: true, user: session }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "").trim();

    if (!email || !password) {
      return new Response(
        JSON.stringify({ ok: false, error: "Credenciales incompletas." }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    if (!env.DB) {
      return new Response(
        JSON.stringify({ ok: false, error: "Servicio de base de datos no disponible." }),
        { status: 503, headers: { "Content-Type": "application/json" } }
      );
    }

    const passwordHash = await sha256Hex(password);
    const user = await env.DB.prepare(
      "SELECT id, email, nombre, rol, dni FROM usuarios WHERE LOWER(email) = ?1 AND password_hash = ?2 LIMIT 1"
    )
      .bind(email, passwordHash)
      .first();

    if (!user) {
      return new Response(
        JSON.stringify({ ok: false, error: "Credenciales invalidas o acceso no autorizado." }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }

    const payloadObj = {
      id: user.id,
      email: user.email,
      nombre: user.nombre,
      rol: user.rol,
      dni: user.dni,
      exp: Date.now() + 28800000
    };
    const b64Payload = btoa(JSON.stringify(payloadObj));
    const signature = await signPayload(b64Payload, env);
    const sessionToken = `${b64Payload}.${signature}`;

    return new Response(
      JSON.stringify({
        ok: true,
        session_token: sessionToken,
        user: payloadObj
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: "Error interno de autenticacion." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
