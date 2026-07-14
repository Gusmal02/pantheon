"""
Wrapper mínimo de Ollama como LLM local para Hermes.

No requiere dependencias extra — usa httpx que ya está en pyproject.toml.
Implementa el mismo contrato que BaseChatModel.invoke() de LangChain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from pantheon.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class _OllamaResponse:
    """Simula el .content de un BaseChatModel response."""
    content: str

    # Compatibilidad con código que llama .type
    type: str = "ai"


class OllamaLLM:
    """
    LLM local vía Ollama HTTP API (/api/chat).

    Args:
        model    — nombre del modelo Ollama (default: settings.ollama_model)
        base_url — URL base de Ollama (default: settings.ollama_base_url)
        timeout  — timeout en segundos para cada llamada (default: 30)
    """

    def __init__(
        self,
        model: str = settings.ollama_model,
        base_url: str = settings.ollama_base_url,
        timeout: float = 30.0,
    ) -> None:
        self._model   = model
        self._url     = base_url.rstrip("/") + "/api/chat"
        self._timeout = timeout

    def invoke(self, messages: list[Any]) -> _OllamaResponse:
        """
        Envía una lista de mensajes a Ollama y devuelve la respuesta.

        Args:
            messages — lista de objetos con atributos .type y .content
                       (langchain_core SystemMessage / HumanMessage)
                       o cualquier objeto con .content

        Returns:
            _OllamaResponse con .content como string.
        """
        ollama_messages = []
        for msg in messages:
            msg_type = getattr(msg, "type", "human")
            role = "system" if msg_type == "system" else "user"
            content = getattr(msg, "content", str(msg))
            ollama_messages.append({"role": role, "content": content})

        try:
            r = httpx.post(
                self._url,
                json={"model": self._model, "messages": ollama_messages, "stream": False},
                timeout=self._timeout,
            )
            r.raise_for_status()
            text = r.json()["message"]["content"]
            return _OllamaResponse(content=text)
        except Exception as exc:
            logger.warning("OllamaLLM.invoke error (%s): %s", self._model, exc)
            return _OllamaResponse(content="")

    @classmethod
    def try_create(
        cls,
        model: str = settings.ollama_model,
        base_url: str = settings.ollama_base_url,
    ) -> Optional["OllamaLLM"]:
        """
        Intenta conectar con Ollama y crea una instancia si está disponible.

        Returns None si Ollama no responde (modo sin LLM: fallbacks deterministas).
        """
        try:
            r = httpx.get(base_url.rstrip("/") + "/api/tags", timeout=2.0)
            if r.status_code == 200:
                logger.info("Ollama disponible en %s — usando modelo %s", base_url, model)
                return cls(model=model, base_url=base_url)
        except Exception:
            pass
        logger.info("Ollama no disponible — Hermes usará fallbacks deterministas")
        return None
