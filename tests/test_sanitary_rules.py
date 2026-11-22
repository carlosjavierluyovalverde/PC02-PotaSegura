"""
Suite de Pruebas Automatizadas (Unitarias y de Seguridad) para PotaSegura.
Ejecutada en el pipeline CI/CD de GitHub Actions con pytest.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.sanitary_rules import (
    evaluate_cold_chain_temperature,
    evaluate_six_hour_exposure_window,
    generate_qr_hmac_signature,
    verify_qr_hmac_signature,
    validate_citizen_geofence,
    sanitize_input_text,
)


def test_cold_chain_safe_temperature_green():
    """HU-08: Temperatura < 5.0 C debe asignar Semaforo VERDE (CONFORME_VERDE)."""
    result = evaluate_cold_chain_temperature(3.4)
    assert result["semaforo"] == "VERDE"
    assert result["dictamen"] == "CONFORME_VERDE"


def test_cold_chain_warning_temperature_yellow():
    """HU-08: Temperatura entre 5.0 C y 7.9 C debe asignar Semaforo AMARILLO."""
    result = evaluate_cold_chain_temperature(6.2)
    assert result["semaforo"] == "AMARILLO"
    assert result["dictamen"] == "OBSERVADO_AMARILLO"


def test_cold_chain_critical_revocation_red():
    """HU-09: Temperatura >= 8.0 C debe revocar el sello y forzar Semaforo ROJO."""
    result = evaluate_cold_chain_temperature(8.5)
    assert result["semaforo"] == "ROJO"
    assert result["dictamen"] == "REVOCADO_ROJO"


def test_six_hour_window_calculation_and_expiration():
    """HU-05: T_limite = T_compra + 6h; superar 6.0 horas invalida el lote por histamina."""
    safe_window = evaluate_six_hour_exposure_window("07:30", 3.5)
    assert safe_window["hora_limite"] == "13:30"
    assert safe_window["estado_lote"] == "ACTIVO_SEGURO"
    assert safe_window["apto_consumo"] is True

    warning_window = evaluate_six_hour_exposure_window("06:00", 5.5)
    assert warning_window["hora_limite"] == "12:00"
    assert warning_window["estado_lote"] == "ALERTA_REPOSICION"

    expired_window = evaluate_six_hour_exposure_window("04:30", 6.5)
    assert expired_window["hora_limite"] == "10:30"
    assert expired_window["estado_lote"] == "EXPIRADO_6H"
    assert expired_window["apto_consumo"] is False
    assert expired_window["semaforo"] == "ROJO"


def test_hmac_sha256_qr_signature_integrity():
    """HU-03: El distintivo QR firmado con HMAC-SHA256 debe rechazar cualquier adulteracion."""
    fixture_seed = os.environ.get("QR_TEST_SEED", "test-fixture-value")
    sig = generate_qr_hmac_signature("PUESTO-VMT-042", "LOTE-01", "GUIA-98412", fixture_seed)
    assert len(sig) == 64
    assert verify_qr_hmac_signature("PUESTO-VMT-042", "LOTE-01", "GUIA-98412", sig, fixture_seed) is True
    # Intento de suplantacion por puesto informal
    assert verify_qr_hmac_signature("PUESTO-FALSO-99", "LOTE-01", "GUIA-98412", sig, fixture_seed) is False


def test_geofence_proximity_anti_sabotage():
    """HU-12: Denuncias ciudadanas solo se admiten dentro de un radio <= 50 metros."""
    valid_report = validate_citizen_geofence(18.0)
    assert valid_report["geocerca_valida"] is True
    assert valid_report["estado"] == "ACEPTADA"

    blocked_report = validate_citizen_geofence(125.0)
    assert blocked_report["geocerca_valida"] is False
    assert blocked_report["estado"] == "RECHAZADA_FUERA_DE_RADIO"


def test_xss_input_sanitization():
    """Seguridad Shift-Left: Bloqueo de etiquetas maliciosas XSS en formularios."""
    malicious = "<script>alert('xss')</script>Cooler sin hielo"
    cleaned = sanitize_input_text(malicious)
    assert "<" not in cleaned
    assert ">" not in cleaned
    assert "Cooler sin hielo" in cleaned
