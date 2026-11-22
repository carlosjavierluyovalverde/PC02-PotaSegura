import { verifyBearerToken } from "./auth.js";

export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const session = await verifyBearerToken(request, env);
    if (!session) {
      return new Response(
        JSON.stringify({ ok: false, error: "Acceso denegado. Se requiere autenticacion RBAC." }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }

    if (!env.DB) {
      return new Response(
        JSON.stringify({ ok: false, error: "Base de datos Cloudflare D1 no vinculada." }),
        { status: 503, headers: { "Content-Type": "application/json" } }
      );
    }

    const puestosRes = await env.DB.prepare("SELECT * FROM puestos ORDER BY codigo_puesto ASC").all();
    const lotesRes = await env.DB.prepare("SELECT * FROM lotes_pota ORDER BY id_lote DESC").all();
    const actasRes = await env.DB.prepare("SELECT * FROM actas_inspeccion ORDER BY fecha_hora DESC").all();
    const denunciasRes = await env.DB.prepare("SELECT * FROM denuncias_ciudadanas ORDER BY fecha_reporte DESC").all();

    return new Response(
      JSON.stringify({
        ok: true,
        puestos: puestosRes.results || [],
        lotes: lotesRes.results || [],
        actas: actasRes.results || [],
        denuncias: denunciasRes.results || []
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: "Error consultando Cloudflare D1." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const session = await verifyBearerToken(request, env);
    if (!session) {
      return new Response(
        JSON.stringify({ ok: false, error: "Acceso denegado. Se requiere autenticacion RBAC." }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }

    if (!env.DB) {
      return new Response(
        JSON.stringify({ ok: false, error: "Binding D1 no disponible." }),
        { status: 503, headers: { "Content-Type": "application/json" } }
      );
    }

    const body = await request.json();
    const action = String(body.action || "");

    if (action === "REGISTRAR_LOTE") {
      if (session.rol !== "CARRETILLERO" && session.rol !== "ADMIN") {
        return new Response(
          JSON.stringify({ ok: false, error: "Rol no autorizado para registrar lotes." }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }

      const id_lote = String(body.id_lote || "").trim();
      const codigo_puesto = String(body.codigo_puesto || "PUESTO-VMT-042").trim();
      const terminal_origen = String(body.terminal_origen || "").trim();
      const comprobante_sanipes = String(body.comprobante_sanipes || "").trim();
      const peso_kg = Number(body.peso_kg || 20);
      const hora_compra = String(body.hora_compra || "06:30").trim();
      const hora_limite_6h = String(body.hora_limite_6h || "12:30").trim();
      const hielo = body.hielo_proporcion_1a1 ? 1 : 0;
      const drenaje = body.drenaje_operativo ? 1 : 0;
      const cooler = body.cooler_hermetico ? 1 : 0;
      const estado_lote = String(body.estado_lote || "ACTIVO_SEGURO");

      await env.DB.prepare(
        `INSERT OR REPLACE INTO lotes_pota
         (id_lote, codigo_puesto, terminal_origen, comprobante_sanipes, peso_kg, hora_compra, hora_limite_6h, hielo_proporcion_1a1, drenaje_operativo, cooler_hermetico, estado_lote)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
      )
        .bind(
          id_lote,
          codigo_puesto,
          terminal_origen,
          comprobante_sanipes,
          peso_kg,
          hora_compra,
          hora_limite_6h,
          hielo,
          drenaje,
          cooler,
          estado_lote
        )
        .run();

      return new Response(
        JSON.stringify({ ok: true, message: "Lote registrado en Cloudflare D1." }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    if (action === "EMITIR_ACTA") {
      if (session.rol !== "INSPECTOR" && session.rol !== "ADMIN") {
        return new Response(
          JSON.stringify({ ok: false, error: "Rol no autorizado para emitir actas de fiscalizacion." }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }

      const id_acta = String(body.id_acta || "").trim();
      const codigo_puesto = String(body.codigo_puesto || "").trim();
      const inspector_nombre = String(session.nombre || "").trim();
      const inspector_dni = String(session.dni || "").trim();
      const temperatura_medida = Number(body.temperatura_medida || 0);
      const dictamen = String(body.dictamen || "CONFORME_VERDE").trim();
      const observaciones = String(body.observaciones || "").trim();
      const audit_hash_sha256 = String(body.audit_hash_sha256 || "").trim();
      const nuevo_semaforo =
        dictamen === "CONFORME_VERDE"
          ? "VERDE"
          : dictamen === "OBSERVADO_AMARILLO"
          ? "AMARILLO"
          : "ROJO";

      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO actas_inspeccion
           (id_acta, codigo_puesto, inspector_nombre, inspector_dni, temperatura_medida, dictamen, observaciones, audit_hash_sha256)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
        ).bind(
          id_acta,
          codigo_puesto,
          inspector_nombre,
          inspector_dni,
          temperatura_medida,
          dictamen,
          observaciones,
          audit_hash_sha256
        ),
        env.DB.prepare(
          "UPDATE puestos SET semaforo_estado = ?1, ultima_actualizacion = CURRENT_TIMESTAMP WHERE codigo_puesto = ?2"
        ).bind(nuevo_semaforo, codigo_puesto)
      ]);

      return new Response(
        JSON.stringify({ ok: true, message: "Acta digital y semaforo actualizados en Cloudflare D1." }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ ok: false, error: "Accion no permitida." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: "Error procesando transaccion en Cloudflare D1." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
