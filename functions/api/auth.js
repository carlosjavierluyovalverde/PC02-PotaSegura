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

    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS control_intentos (email TEXT PRIMARY KEY, intentos INTEGER DEFAULT 0, bloqueado_hasta INTEGER DEFAULT 0)"
    ).run();

    const now = Date.now();
    const control = await env.DB.prepare(
      "SELECT intentos, bloqueado_hasta FROM control_intentos WHERE email = ?1"
    )
      .bind(email)
      .first();

    if (control && control.bloqueado_hasta && now < control.bloqueado_hasta) {
      const restantesSegundos = Math.ceil((control.bloqueado_hasta - now) / 1000);
      return new Response(
        JSON.stringify({
          ok: false,
          error: `Cuenta bloqueada temporalmente por exceso de intentos fallidos. Espere ${restantesSegundos} segundos para volver a intentar.`,
          bloqueado: true,
          segundos_restantes: restantesSegundos
        }),
        { status: 429, headers: { "Content-Type": "application/json" } }
      );
    }

    const passwordHash = await sha256Hex(password);
    const user = await env.DB.prepare(
      "SELECT id, email, nombre, rol, dni FROM usuarios WHERE LOWER(email) = ?1 AND password_hash = ?2 LIMIT 1"
    )
      .bind(email, passwordHash)
      .first();

    if (!user) {
      const prevIntentos = control ? Number(control.intentos || 0) : 0;
      const nuevosIntentos = prevIntentos + 1;
      const maxIntentos = 5;
      let bloqueadoHasta = 0;
      let mensajeError = `Credenciales invalidas. Intento fallido ${nuevosIntentos} de ${maxIntentos}.`;

      if (nuevosIntentos >= maxIntentos) {
        bloqueadoHasta = now + 180000;
        mensajeError = "Demasiados intentos fallidos. Su cuenta ha sido bloqueada temporalmente por 3 minutos por seguridad.";
      }

      await env.DB.prepare(
        "INSERT INTO control_intentos (email, intentos, bloqueado_hasta) VALUES (?1, ?2, ?3) ON CONFLICT(email) DO UPDATE SET intentos = ?2, bloqueado_hasta = ?3"
      )
        .bind(email, nuevosIntentos, bloqueadoHasta)
        .run();

      const statusCode = nuevosIntentos >= maxIntentos ? 429 : 401;
      return new Response(
        JSON.stringify({
          ok: false,
          error: mensajeError,
          intentos: nuevosIntentos,
          max_intentos: maxIntentos,
          bloqueado: nuevosIntentos >= maxIntentos,
          segundos_restantes: nuevosIntentos >= maxIntentos ? 180 : 0
        }),
        { status: statusCode, headers: { "Content-Type": "application/json" } }
      );
    }

    if (control && (control.intentos > 0 || control.bloqueado_hasta > 0)) {
      await env.DB.prepare(
        "UPDATE control_intentos SET intentos = 0, bloqueado_hasta = 0 WHERE email = ?1"
      )
        .bind(email)
        .run();
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
