export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    if (!env.DB) {
      return new Response(
        JSON.stringify({ ok: false, error: "Servicio de consulta no disponible." }),
        { status: 503, headers: { "Content-Type": "application/json" } }
      );
    }

    const url = new URL(request.url);
    const codigo = String(url.searchParams.get("puesto") || "PUESTO-VMT-042").trim();

    const puesto = await env.DB.prepare(
      "SELECT codigo_puesto, comerciante_nombre, ubicacion_autorizada, carnet_sanidad, carnet_estado, semaforo_estado, especie_declarada, qr_hmac_signature, ultima_actualizacion FROM puestos WHERE codigo_puesto = ?1 LIMIT 1"
    )
      .bind(codigo)
      .first();

    if (!puesto) {
      return new Response(
        JSON.stringify({ ok: false, error: "Puesto no encontrado en el padron municipal." }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }

    const lote = await env.DB.prepare(
      "SELECT terminal_origen, comprobante_sanipes, hora_compra, hora_limite_6h, estado_lote FROM lotes_pota WHERE codigo_puesto = ?1 ORDER BY id_lote DESC LIMIT 1"
    )
      .bind(codigo)
      .first();

    const acta = await env.DB.prepare(
      "SELECT temperatura_medida, dictamen, fecha_hora FROM actas_inspeccion WHERE codigo_puesto = ?1 ORDER BY fecha_hora DESC LIMIT 1"
    )
      .bind(codigo)
      .first();

    return new Response(
      JSON.stringify({
        ok: true,
        puesto,
        lote: lote || null,
        acta: acta || null
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: "Error en consulta publica." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    if (!env.DB) {
      return new Response(
        JSON.stringify({ ok: false, error: "Servicio no disponible." }),
        { status: 503, headers: { "Content-Type": "application/json" } }
      );
    }

    const body = await request.json();
    const codigo_puesto = String(body.codigo_puesto || "").trim();
    const motivo = String(body.motivo || "").trim();
    const comentario = String(body.comentario || "").trim();
    const distancia_metros = Number(body.distancia_metros || 0);
    const geocerca_valida = distancia_metros >= 0 && distancia_metros <= 50 ? 1 : 0;

    if (!geocerca_valida) {
      return new Response(
        JSON.stringify({
          ok: false,
          error: "Denuncia bloqueada por geocerca: distancia superior a 50 metros."
        }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }

    await env.DB.prepare(
      `INSERT INTO denuncias_ciudadanas (codigo_puesto, motivo, comentario, distancia_metros, geocerca_valida)
       VALUES (?1, ?2, ?3, ?4, ?5)`
    )
      .bind(codigo_puesto, motivo, comentario, distancia_metros, geocerca_valida)
      .run();

    return new Response(
      JSON.stringify({
        ok: true,
        message: "Alerta sanitaria georreferenciada registrada en Cloudflare D1."
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: "Error al registrar alerta ciudadana." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
