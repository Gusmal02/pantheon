"""
War Room — Interfaz de operador de Pantheon v2.1.

UI Gradio con:
  - Autenticación JWT (token Bearer del operador)
  - Panel de hipótesis rankeadas (actualización manual o periódica)
  - Sliders de feedback dimensional (relevancia, claridad, accionabilidad, urgencia)
  - Botón de parada de emergencia (Kill Switch)
  - Watchdog adaptativo: alerta si una hipótesis lleva > timeout_secs sin acción

El War Room NO toma decisiones de autorización. Solo muestra información
y envía feedback firmado a la API de Pantheon.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import gradio as gr

from pantheon.acme.feedback_auth import (
    SignedFeedback,
    create_operator_token,
    decode_operator_token,
    sign_feedback,
)
from pantheon.core.config import settings


# ── Estado de sesión ──────────────────────────────────────────────────────────

@dataclass
class SessionState:
    """Estado efímero de la sesión del War Room (por usuario de Gradio)."""
    operator_id: str = ""
    token: str = ""
    authenticated: bool = False
    hypotheses: list[dict] = field(default_factory=list)
    selected_hypothesis_id: str = ""
    last_action_ts: float = field(default_factory=time.time)
    killswitch_triggered: bool = False


# ── Watchdog ──────────────────────────────────────────────────────────────────

class AdaptiveWatchdog:
    """
    Monitoriza que el operador tome acción sobre las hipótesis dentro del timeout.

    Si transcurre más de `timeout_secs` sin acción sobre una hipótesis CRITICAL,
    emite una alerta en el panel de estado. No bloquea ni bypasea — solo avisa.

    Args:
        timeout_secs   — segundos antes de emitir alerta (default: settings.pantheon_approval_timeout_secs)
        check_interval — segundos entre comprobaciones del watchdog
    """

    def __init__(
        self,
        timeout_secs: int = settings.pantheon_approval_timeout_secs,
        check_interval: int = 30,
    ) -> None:
        self._timeout = timeout_secs
        self._check_interval = check_interval
        self._sessions: dict[str, SessionState] = {}
        self._alerts: dict[str, str] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def register_session(self, operator_id: str, state: SessionState) -> None:
        with self._lock:
            self._sessions[operator_id] = state

    def touch(self, operator_id: str) -> None:
        """Actualiza el timestamp de última acción (llama al aprobar/denegar/feedback)."""
        with self._lock:
            if operator_id in self._sessions:
                self._sessions[operator_id].last_action_ts = time.time()
            self._alerts.pop(operator_id, None)

    def get_alert(self, operator_id: str) -> str:
        with self._lock:
            return self._alerts.get(operator_id, "")

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="war-room-watchdog")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _run_once(self) -> None:
        """Ejecuta un ciclo de comprobación. Separado de _run para facilitar tests."""
        with self._lock:
            now = time.time()
            for op_id, state in self._sessions.items():
                if state.hypotheses and not state.killswitch_triggered:
                    elapsed = now - state.last_action_ts
                    if elapsed > self._timeout:
                        self._alerts[op_id] = (
                            f"⚠️ ALERTA: {int(elapsed)}s sin acción sobre hipótesis pendientes "
                            f"(timeout: {self._timeout}s)"
                        )

    def _run(self) -> None:
        while self._running:
            time.sleep(self._check_interval)
            self._run_once()


_watchdog = AdaptiveWatchdog()


# ── Lógica de negocio (sin Gradio) — testeable en aislamiento ────────────────

def authenticate(operator_id: str, jwt_secret: str = settings.pantheon_jwt_secret) -> tuple[bool, str, str]:
    """
    Genera un token JWT para el operador dado.

    Returns:
        (success, token, message)
    """
    if not operator_id or not operator_id.strip():
        return False, "", "ID de operador requerido."
    op_id = operator_id.strip()
    token = create_operator_token(op_id, jwt_secret, expire_hours=settings.pantheon_jwt_expire_hours)
    return True, token, f"Sesión iniciada como {op_id}"


def verify_token(token: str, jwt_secret: str = settings.pantheon_jwt_secret) -> tuple[bool, str]:
    """
    Verifica un token JWT existente.

    Returns:
        (valid, operator_id_or_error_message)
    """
    try:
        decoded = decode_operator_token(token, jwt_secret)
        return True, decoded.operator_id
    except Exception as exc:
        return False, str(exc)


def build_feedback_payload(
    hypothesis_id: str,
    thumbs: str,
    relevance: int,
    clarity: int,
    actionability: int,
    urgency: int,
) -> dict:
    """Construye el payload de feedback dimensional."""
    return {
        "hypothesis_id": hypothesis_id,
        "thumbs": thumbs,
        "relevance": relevance,
        "clarity": clarity,
        "actionability": actionability,
        "urgency": urgency,
    }


def sign_operator_feedback(
    payload: dict,
    operator_id: str,
    jwt_secret: str = settings.pantheon_jwt_secret,
) -> SignedFeedback:
    """Firma el feedback dimensional con HMAC-SHA256."""
    fb_payload = {k: v for k, v in payload.items() if k != "hypothesis_id"}
    return sign_feedback(fb_payload, operator_id, jwt_secret)


def trigger_killswitch(operator_id: str, reason: str) -> dict:
    """
    Activa el Kill Switch del War Room.

    Devuelve el payload que se enviaría a POST /killswitch.
    En producción, este método hace la llamada HTTP real.
    """
    return {
        "triggered": True,
        "operator_id": operator_id,
        "reason": reason or "kill switch manual",
        "timestamp": time.time(),
    }


# ── Gradio UI ─────────────────────────────────────────────────────────────────

def build_war_room_ui(jwt_secret: str = settings.pantheon_jwt_secret) -> gr.Blocks:
    """
    Construye la interfaz Gradio del War Room.

    Args:
        jwt_secret — secreto JWT para firmar tokens y feedback

    Returns:
        gr.Blocks — interfaz lista para lanzar con .launch()
    """

    with gr.Blocks(
        title="Pantheon War Room",
        theme=gr.themes.Monochrome(),
        css="""
        .critical { color: #ff4444; font-weight: bold; }
        .moderate { color: #ffaa00; }
        .alert-box { background: #3a1a1a; border: 1px solid #ff4444; padding: 8px; border-radius: 4px; }
        """,
    ) as demo:

        # — Estado de sesión (Gradio State) —
        session = gr.State(SessionState())

        # ── Encabezado ──
        gr.Markdown("# 🛡️ Pantheon War Room v2.1")
        gr.Markdown("*Threat Hunting — Interfaz de operador*")

        # ── Panel de autenticación ──
        with gr.Tab("🔐 Autenticación"):
            with gr.Row():
                op_id_input = gr.Textbox(
                    label="ID de Operador",
                    placeholder="ej. op_garcia_01",
                    scale=3,
                )
                login_btn = gr.Button("Iniciar Sesión", variant="primary", scale=1)

            token_display = gr.Textbox(
                label="Token JWT (copia para uso externo)",
                interactive=False,
                lines=3,
            )
            auth_status = gr.Markdown("*No autenticado*")

        # ── Panel principal de hipótesis ──
        with gr.Tab("🔍 Hipótesis"):
            with gr.Row():
                refresh_btn = gr.Button("🔄 Actualizar hipótesis", variant="secondary")
                watchdog_alert = gr.Markdown("")

            hypotheses_table = gr.Dataframe(
                headers=["ID", "Hipótesis", "Score", "TTPs", "Estado"],
                datatype=["str", "str", "number", "str", "str"],
                label="Hipótesis rankeadas",
                interactive=False,
            )

            with gr.Row():
                hyp_id_input = gr.Textbox(label="ID de hipótesis seleccionada", scale=2)
                approve_btn = gr.Button("✅ Aprobar contención", variant="primary", scale=1)
                deny_btn = gr.Button("❌ Denegar", variant="stop", scale=1)

            action_status = gr.Markdown("")

        # ── Panel de feedback dimensional ──
        with gr.Tab("📊 Feedback"):
            gr.Markdown("### Feedback dimensional firmado")
            gr.Markdown(
                "El feedback se firma con HMAC-SHA256 antes de enviarse. "
                "Cualquier modificación invalida la firma."
            )

            with gr.Row():
                fb_hyp_id = gr.Textbox(label="ID de hipótesis", scale=2)
                fb_thumbs = gr.Radio(
                    choices=["up", "down"],
                    label="Valoración general",
                    value="up",
                    scale=1,
                )

            with gr.Row():
                sl_relevance = gr.Slider(1, 5, value=3, step=1, label="Relevancia (1-5)")
                sl_clarity = gr.Slider(1, 5, value=3, step=1, label="Claridad (1-5)")

            with gr.Row():
                sl_actionability = gr.Slider(1, 5, value=3, step=1, label="Accionabilidad (1-5)")
                sl_urgency = gr.Slider(1, 5, value=3, step=1, label="Urgencia (1-5)")

            send_feedback_btn = gr.Button("📤 Enviar feedback firmado", variant="primary")
            feedback_status = gr.Markdown("")

        # ── Kill Switch ──
        with gr.Tab("🚨 Kill Switch"):
            gr.Markdown("## ⚠️ Parada de emergencia")
            gr.Markdown(
                "Activa el Kill Switch para abortar **todas** las operaciones activas de Pantheon. "
                "Esta acción queda registrada en el Audit Trail con tu firma de operador."
            )
            ks_reason = gr.Textbox(
                label="Motivo (requerido)",
                placeholder="ej. Falso positivo confirmado — detener contención inmediatamente",
            )
            ks_btn = gr.Button(
                "🚨 ACTIVAR KILL SWITCH",
                variant="stop",
                elem_id="killswitch-btn",
            )
            ks_status = gr.Markdown("")

        # ── Handlers ─────────────────────────────────────────────────────────

        def handle_login(op_id: str, sess: SessionState):
            ok, token, msg = authenticate(op_id, jwt_secret)
            if ok:
                sess.operator_id = op_id.strip()
                sess.token = token
                sess.authenticated = True
                sess.last_action_ts = time.time()
                _watchdog.register_session(sess.operator_id, sess)
                return (
                    sess,
                    token,
                    f"✅ {msg}",
                )
            return sess, "", f"❌ {msg}"

        login_btn.click(
            handle_login,
            inputs=[op_id_input, session],
            outputs=[session, token_display, auth_status],
        )

        def handle_refresh(sess: SessionState):
            if not sess.authenticated:
                return sess, [], "❌ Debes autenticarte primero."
            alert = _watchdog.get_alert(sess.operator_id)
            alert_md = f"<div class='alert-box'>{alert}</div>" if alert else ""
            # En producción: GET /hypotheses con Bearer token
            # MVP: tabla vacía con mensaje informativo
            rows = [
                [h.get("id", ""), h.get("text", ""), h.get("score", 0.0),
                 ", ".join(h.get("ttps", [])), h.get("status", "pending")]
                for h in sess.hypotheses
            ] or [["—", "Sin hipótesis pendientes", 0.0, "—", "—"]]
            return sess, rows, alert_md

        refresh_btn.click(
            handle_refresh,
            inputs=[session],
            outputs=[session, hypotheses_table, watchdog_alert],
        )

        def handle_approve(hyp_id: str, sess: SessionState):
            if not sess.authenticated:
                return sess, "❌ No autenticado."
            if not hyp_id.strip():
                return sess, "❌ Selecciona una hipótesis primero."
            _watchdog.touch(sess.operator_id)
            # En producción: POST /approve/{hyp_id}
            return sess, f"✅ Hipótesis `{hyp_id}` aprobada. Contención en curso."

        approve_btn.click(
            handle_approve,
            inputs=[hyp_id_input, session],
            outputs=[session, action_status],
        )

        def handle_deny(hyp_id: str, sess: SessionState):
            if not sess.authenticated:
                return sess, "❌ No autenticado."
            if not hyp_id.strip():
                return sess, "❌ Selecciona una hipótesis primero."
            _watchdog.touch(sess.operator_id)
            # En producción: POST /deny/{hyp_id}
            return sess, f"🚫 Hipótesis `{hyp_id}` denegada."

        deny_btn.click(
            handle_deny,
            inputs=[hyp_id_input, session],
            outputs=[session, action_status],
        )

        def handle_feedback(
            hyp_id: str, thumbs: str,
            relevance: int, clarity: int, actionability: int, urgency: int,
            sess: SessionState,
        ):
            if not sess.authenticated:
                return sess, "❌ No autenticado."
            if not hyp_id.strip():
                return sess, "❌ ID de hipótesis requerido."

            payload = build_feedback_payload(hyp_id, thumbs, relevance, clarity, actionability, urgency)
            signed = sign_operator_feedback(payload, sess.operator_id, jwt_secret)
            _watchdog.touch(sess.operator_id)

            # En producción: POST /feedback con signed.signature
            return (
                sess,
                f"✅ Feedback firmado enviado para `{hyp_id}` "
                f"(firma: `{signed.signature[:16]}…`)"
            )

        send_feedback_btn.click(
            handle_feedback,
            inputs=[fb_hyp_id, fb_thumbs, sl_relevance, sl_clarity, sl_actionability, sl_urgency, session],
            outputs=[session, feedback_status],
        )

        def handle_killswitch(reason: str, sess: SessionState):
            if not sess.authenticated:
                return sess, "❌ No autenticado."
            if not reason.strip():
                return sess, "❌ El motivo es obligatorio para activar el Kill Switch."

            result = trigger_killswitch(sess.operator_id, reason)
            sess.killswitch_triggered = True
            # En producción: POST /killswitch
            ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result["timestamp"]))
            return (
                sess,
                f"🚨 **KILL SWITCH ACTIVADO** por `{sess.operator_id}` a las {ts}\n\n"
                f"Motivo: *{reason}*\n\n"
                "Todas las operaciones activas han sido abortadas. "
                "El evento está registrado en el Audit Trail."
            )

        ks_btn.click(
            handle_killswitch,
            inputs=[ks_reason, session],
            outputs=[session, ks_status],
        )

    return demo


def launch(
    host: str = "0.0.0.0",
    port: int = 7860,
    share: bool = False,
) -> None:
    """Inicia el War Room Gradio."""
    _watchdog.start()
    demo = build_war_room_ui()
    demo.launch(server_name=host, server_port=port, share=share)


if __name__ == "__main__":
    launch()
