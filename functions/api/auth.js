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

    if (env.DB) {
      const stmt = env.DB.prepare(
        "SELECT id, email, nombre, rol, dni FROM usuarios WHERE LOWER(email) = ?1 AND password_hash = ?2 LIMIT 1"
      ).bind(email, password);
      const user = await stmt.first();

      if (!user) {
        return new Response(
          JSON.stringify({ ok: false, error: "Credenciales invalidas o usuario no autorizado." }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({
          ok: true,
          user: {
            id: user.id,
            email: user.email,
            nombre: user.nombre,
            rol: user.rol,
            dni: user.dni,
            source: "Cloudflare D1 SQL"
          }
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ ok: false, error: "Binding D1 no disponible." }),
      { status: 503, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: "Error interno de autenticacion." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
