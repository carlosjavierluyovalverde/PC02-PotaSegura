import hashlib
import hmac
import re
from typing import Dict, Any


def evaluate_cold_chain_temperature(temp_celsius: float) -> Dict[str, str]:
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
    codigo_puesto: str, id_lote: str, comprobante_sanipes: str, signing_seed: str
) -> str:
    if not signing_seed or len(signing_seed) < 8:
        raise ValueError("La semilla de firma debe tener al menos 8 caracteres.")
    message = f"{codigo_puesto}|{id_lote}|{comprobante_sanipes}".encode("utf-8")
    seed_bytes = signing_seed.encode("utf-8")
    return hmac.new(seed_bytes, message, hashlib.sha256).hexdigest()


def verify_qr_hmac_signature(
    codigo_puesto: str,
    id_lote: str,
    comprobante_sanipes: str,
    provided_signature: str,
    signing_seed: str,
) -> bool:
    expected = generate_qr_hmac_signature(
        codigo_puesto, id_lote, comprobante_sanipes, signing_seed
    )
    return hmac.compare_digest(expected, provided_signature)


def validate_citizen_geofence(distance_meters: float) -> Dict[str, Any]:
    if distance_meters < 0:
        raise ValueError("La distancia GPS no puede ser negativa.")
    allowed = distance_meters <= 50.0
    return {
        "geocerca_valida": allowed,
        "distancia_metros": distance_meters,
        "estado": "ACEPTADA" if allowed else "RECHAZADA_FUERA_DE_RADIO",
    }


def sanitize_input_text(raw_text: str) -> str:
    cleaned = re.sub(r"[<>\"']", "", str(raw_text or ""))
    return cleaned.strip()
