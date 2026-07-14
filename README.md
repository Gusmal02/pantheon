# Pantheon v2.1

> **Plataforma autónoma de caza de amenazas con memoria episódica**

---

## ¿Qué es Pantheon?

Pantheon es un sistema de ciberseguridad defensiva que ayuda a los equipos de seguridad a detectar, investigar y contener amenazas en redes corporativas de forma más rápida y confiable. En lugar de esperar a que un analista revise manualmente cientos de alertas, Pantheon analiza el tráfico de red de forma continua, identifica patrones sospechosos y genera hipótesis sobre posibles ataques, priorizadas según el contexto y el estilo de trabajo de cada analista.

Piénsalo como un asistente de seguridad que nunca duerme: observa todo lo que pasa en la red, aprende de las decisiones pasadas del equipo y propone acciones concretas, siempre dejando al humano la última palabra.

---

## ¿Para qué sirve?

- **Detectar ataques a tiempo** — Identifica comportamientos anómalos en el tráfico de red antes de que causen daño real.
- **Priorizar lo importante** — Ordena las alertas según la probabilidad real de que sean una amenaza, adaptándose a cada analista.
- **Proponer respuestas** — Sugiere acciones de contención (bloquear una IP, aislar un equipo, capturar memoria) con validación automática de seguridad antes de ejecutarlas.
- **Mantener un registro inviolable** — Cada acción queda registrada en un sistema de auditoría a prueba de manipulaciones, útil para análisis forense y cumplimiento normativo.
- **Aprender continuamente** — Incorpora el feedback del equipo para mejorar con el tiempo sin depender de reentrenamientos costosos.

---

## ¿Quién lo usa?

Pantheon está diseñado para **analistas de seguridad** (SOC Tier 2/3) que investigan incidentes complejos, y para **equipos de respuesta a incidentes** que necesitan actuar rápido con la confianza de que las acciones automatizadas son seguras.

---

## ¿Qué lo hace diferente?

La mayoría de las herramientas de seguridad automatizan las acciones de forma ciega. Pantheon hace lo opuesto:

1. **El sistema no decide por sí solo** — La inteligencia artificial genera sugerencias, pero la autorización de cualquier acción real la da siempre un humano o una regla determinista.
2. **Registro a prueba de manipulaciones** — Cada evento queda vinculado criptográficamente al anterior; si alguien toca el log, el sistema lo detecta.
3. **Aprende de tu equipo** — Se adapta al estilo de análisis de cada operador sin comprometer la seguridad del sistema.
4. **Fail-closed por diseño** — Si algo falla (timeout, error de red, sobrecarga), el sistema bloquea en lugar de dejar pasar. La seguridad es el estado por defecto.

---

## Estado del proyecto

| Módulo | Estado |
|---|---|
| Detección de anomalías (Centinela) | ✅ Completo |
| Memoria episódica y búsqueda semántica (Ornith) | ✅ Completo |
| Ranking de hipótesis por analista (Acme) | ✅ Completo |
| Validación de playbooks de contención (Muralla) | ✅ Completo |
| Filtro de logs y protección anti-inyección (Guards) | ✅ Completo |
| Audit Trail con cadena de hashes (Enclave) | ✅ Completo |
| API REST (FastAPI) | ✅ Completo |
| Caché semántico | ✅ Completo |
| Grafo ATT&CK | ✅ Completo |
| Agente de investigación CRAG (Hermes) | ✅ Completo |
| Interfaz de operador con watchdog (War Room) | ✅ Completo |
| Integración bidireccional con Ares v3.2 (Purple Bridge) | ✅ Completo |
| Suite de tests (341 tests, 0 fallos) | ✅ Completo |

---

## Documentación

| Documento | Contenido |
|---|---|
| [INSTRUCTIONS.md](INSTRUCTIONS.md) | Instalación paso a paso |
| [TECHNICAL.md](TECHNICAL.md) | Descripción técnica de cada módulo |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Decisiones de arquitectura y diagramas |

---

## Licencia

MIT — consulta el archivo `LICENSE` para más detalles.

---
---

# Pantheon v2.1

> **Autonomous threat hunting platform with episodic memory**

---

## What is Pantheon?

Pantheon is a defensive cybersecurity system that helps security teams detect, investigate, and contain threats in corporate networks faster and more reliably. Instead of waiting for an analyst to manually review hundreds of alerts, Pantheon continuously analyzes network traffic, identifies suspicious patterns, and generates prioritized hypotheses about potential attacks — adapted to each analyst's working style.

Think of it as a security assistant that never sleeps: it watches everything happening on the network, learns from the team's past decisions, and proposes concrete actions while always leaving the final call to a human.

---

## What does it do?

- **Early threat detection** — Identifies anomalous behavior in network traffic before real damage occurs.
- **Smart prioritization** — Ranks alerts by actual likelihood of being a threat, adapting to each analyst's profile.
- **Response suggestions** — Proposes containment actions (block an IP, isolate a host, capture memory) with automatic safety validation before execution.
- **Tamper-proof audit trail** — Every action is recorded in a cryptographically chained log, useful for forensic analysis and regulatory compliance.
- **Continuous learning** — Incorporates team feedback to improve over time without expensive retraining cycles.

---

## Who uses it?

Pantheon is designed for **security analysts** (SOC Tier 2/3) investigating complex incidents, and for **incident response teams** that need to act quickly with confidence that automated actions are safe.

---

## What makes it different?

Most security tools automate actions blindly. Pantheon does the opposite:

1. **The system never decides alone** — AI generates suggestions, but any real action is authorized by a human or a deterministic rule.
2. **Tamper-proof logging** — Every event is cryptographically linked to the previous one; if someone touches the log, the system detects it.
3. **Learns from your team** — Adapts to each operator's analysis style without compromising system security.
4. **Fail-closed by design** — If anything fails (timeout, network error, overload), the system blocks rather than allows. Security is the default state.

---

## Project Status

| Module | Status |
|---|---|
| Anomaly detection (Centinela) | ✅ Complete |
| Episodic memory & semantic search (Ornith) | ✅ Complete |
| Per-analyst hypothesis ranking (Acme) | ✅ Complete |
| Containment playbook validation (Muralla) | ✅ Complete |
| Log filter & anti-injection protection (Guards) | ✅ Complete |
| Hash-chained Audit Trail (Enclave) | ✅ Complete |
| REST API (FastAPI) | ✅ Complete |
| Semantic cache | ✅ Complete |
| ATT&CK graph | ✅ Complete |
| CRAG investigation agent (Hermes) | ✅ Complete |
| Operator interface with watchdog (War Room) | ✅ Complete |
| Bidirectional Ares v3.2 integration (Purple Bridge) | ✅ Complete |
| Test suite (341 tests, 0 failures) | ✅ Complete |

---

## Documentation

| Document | Content |
|---|---|
| [INSTRUCTIONS.md](INSTRUCTIONS.md) | Step-by-step installation |
| [TECHNICAL.md](TECHNICAL.md) | Technical description of each module |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture decisions and diagrams |

---

## License

MIT — see `LICENSE` file for details.
