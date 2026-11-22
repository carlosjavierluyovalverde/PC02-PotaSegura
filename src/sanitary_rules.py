"""
Modulo de Reglas Sanitarias, Criptografia HMAC-SHA256 y Control RBAC para PotaSegura.
Curso: Proyecto Final de Carrera III (PFC3) - Practica Calificada 2 (PC02).
"""

import hashlib
import hmac
import re
from typing import Dict, Any


def evaluate_cold_chain_temperature(temp_celsius: float) -> Dict[str, str]:
    """
    Evalua la temperatura interna del marisco crudo (Dosidicus gigas) medida in situ.
    - < 5.0 C: Cadena de frio garantizada (VERDE / CONFORME_VERDE)
    - 5.0 C a 7.9 C: Zona de precaucion termica (AMARILLO / OBSERVADO_AMARILLO)
    - >= 8.0 C: Ruptura critica, riesgo de histamina y Vibrio (ROJO / REVOCADO_ROJO)
    """
    if temp_celsius < 5.0:
        return {
            "semaforo": "VERDE",
            "dictamen": "CONFORME_VERDE",
            "accion": "Sello QR activo y verificado",
        }
    if temp_celsius < 8.0:
        return {
            "semaforo": "AMARILLO",
            "dictamen": "OBSERVADO_AMARILLO",
            "accion": "Exigir recarga inmediata de hielo escamado 1:1",
        }
    return {
        "semaforo": "ROJO",
        "dictamen": "REVOCADO_ROJO",
        "accion": "Revocacion automatica de distintivo QR por ruptura de cadena de frio",
    }


def evaluate_six_hour_exposure_window(
    purchase_hour_hhmm: str, elapsed_hours: float
) -> Dict[str, Any]:
    """
    Calcula la ventana maxima de consumo seguro de 6 horas desde la compra en terminal pesquero:
    T_limite = T_compra + 6 horas.
    """
    if elapsed_hours < 0:
        raise ValueError("El tiempo transcurrido no puede ser negativo.")

    parts = purchase_hour_hhmm.strip().split(":")
    hour = int(parts[0])
    minute = int(parts[1]) if len(parts) > 1 else 0
    limit_hour = (hour + 6) % 24
    hora_limite = f"{limit_hour:02d}:{minute:02d}"

    if elapsed_hours > 6.0:
        return {
            "hora_limite": hora_limite,
            "estado_lote": "EXPIRADO_6H",
            "apto_consumo": False,
            "semaforo": "ROJO",
        }
    if elapsed_hours >= 5.0:
        return {
            "hora_limite": hora_limite,
            "estado_lote": "ALERTA_REPOSICION",
            "apto_consumo": True,
            "semaforo": "AMARILLO",
        }
    return {
        "hora_limite": hora_limite,
        "estado_lote": "ACTIVO_SEGURO",
        "apto_consumo": True,
        "semaforo": "VERDE",
    }


def generate_qr_hmac_signature(
    codigo_puesto: str, id_lote: str, comprobante_sanipes: str, secret_key: str
) -> str:
    """
    Genera la firma criptografica HMAC-SHA256 para el distintivo QR municipal,
    mitigando amenazas STRIDE de Spoofing y Tampering.
    """
    if not secret_key or len(secret_key) < 8:
        raise ValueError("La clave secreta HMAC debe tener al menos 8 caracteres.")
    message = f"{codigo_puesto}|{id_lote}|{comprobante_sanipes}".encode("utf-8")
    key_bytes = secret_key.encode("utf-8")
    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def verify_qr_hmac_signature(
    codigo_puesto: str,
    id_lote: str,
    comprobante_sanipes: str,
    provided_signature: str,
    secret_key: str,
) -> bool:
    """
    Verifica en tiempo constante la autenticidad del token QR escaneado en la via publica.
    """
    expected = generate_qr_hmac_signature(
        codigo_puesto, id_lote, comprobante_sanipes, secret_key
    )
    return hmac.compare_digest(expected, provided_signature)


def validate_citizen_geofence(distance_meters: float) -> Dict[str, Any]:
    """
    Valida que el reporte ciudadano provenga de un radio maximo de 50 metros respecto al puesto
    para bloquear sabotaje o denuncias falsas automatizadas.
    """
    if distance_meters < 0:
        raise ValueError("La distancia GPS no puede ser negativa.")
    allowed = distance_meters <= 50.0
    return {
        "geocerca_valida": allowed,
        "distancia_metros": distance_meters,
        "estado": "ACEPTADA" if allowed else "RECHAZADA_FUERA_DE_RADIO",
    }


def sanitize_input_text(raw_text: str) -> str:
    """
    Sanitiza entradas de usuario contra vectores de Cross-Site Scripting (XSS).
    """
    cleaned = re.sub(r"[<>\"']", "", str(raw_text or ""))
    return cleaned.strip()
