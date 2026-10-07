# EcoProcesos

**Un narrador local que cuenta en lenguaje sencillo, y en voz alta, qué está haciendo tu computador con Linux.**

Los monitores del sistema como `top` muestran cientos de procesos, porcentajes y estados
que la mayoría de las personas no sabe interpretar. EcoProcesos lee la actividad del
equipo en tiempo real, decide qué vale la pena contar, lo narra en voz alta y, al terminar
la sesión, genera un informe resumen.

> **Criterio de éxito:** tras escuchar unos dos minutos de narración, una persona sin
> conocimientos técnicos puede explicar con sus propias palabras qué estaba haciendo su
> computador.

> **Estado:** Fase 0 (viabilidad). Hoy solo existe el sondeo descrito abajo. El narrador
> todavía no está implementado.

## Inicio rápido: ejecutar el sondeo de la Fase 0

En el equipo Linux objetivo, como **usuario normal** (no root) y dentro de una sesión de escritorio:

```bash
git clone <url-del-repo> && cd EcoProcesos
PYTHONPATH=src python3 -m ecoprocesos.probe --out probe-report-$(hostname).json
```

Solo usa la biblioteca estándar, así que no hace falta instalar nada.

**Resultado esperado:** una tabla de fuentes de datos, cada una marcada como `OK`, `DEGR`
(disponible en parte; el narrador usará una alternativa) u `OFF` (no disponible). Debajo
aparece el coste de CPU medido al recorrer `/proc`. El informe completo se guarda en JSON.

Ejecútalo dos veces y comparte ambos archivos JSON:

1. Con el equipo en reposo.
2. Con un navegador, un video y algo de carga en marcha.

Opcional: instala `psutil` con `pip install psutil` dentro de un venv para medir también
el recorrido basado en psutil.

## Cómo va a funcionar

```
/proc · cgroups v2 · PSI · systemd · journald · archivos .desktop
        │
[Recolector] → [Normalizador] → [Explicación] → [Priorización] → [Narrativa] → [Voz]
        │              │               │                │
        └──────────────┴─► [Registro de sesión (SQLite)] ◄┘ ──► [Informe final]
```

| Etapa | Qué hace |
|-------|----------|
| Recolector | Lee `/proc`, cgroups y PSI sin privilegios. Cada fuente puede estar OK, degradada o desactivada. |
| Normalizador | Convierte cada lectura en eventos (app nueva, pico de CPU, crecimiento de memoria, presión del sistema), con histéresis para evitar ruido. |
| Explicación | Traduce nombres de procesos a lenguaje sencillo. Usa primero una base de conocimiento curada y después los metadatos de `.desktop` y de los paquetes. Si nada aplica, dice con honestidad "no lo sé". |
| Priorización | Decide qué decir con una función de puntuación pura y configurable. Agrupa por aplicación y aplica tiempos de espera y un límite de tiempo de habla. |
| Voz | Usa el TTS offline [Piper](https://github.com/rhasspy/piper), con `espeak-ng` como respaldo. El audio sale por el protocolo PulseAudio, así que también funciona con PipeWire. |
| Informe | Genera un resumen HTML o PDF de la sesión, incluido lo que no se narró y por qué. |

## Principios de diseño

- **Local y sin conexión por defecto.** Ningún dato sale del equipo sin consentimiento explícito.
- **Solo lectura.** Observa; nunca termina, modifica ni reinicia procesos.
- **Honestidad.** Cada explicación indica su nivel de confianza, y lo desconocido se declara como desconocido.
- **Eventos, no datos crudos.** Narra cambios, no lecturas periódicas.
- **Degradación elegante.** Si una fuente de datos falla, se registra una sola vez y el resto sigue funcionando.
- **El observador no puede ser el problema.** Los límites de consumo de CPU y RAM son requisitos con verificación automática.

## Hoja de ruta

| Fase | Alcance | Estado |
|------|---------|--------|
| 0 | Viabilidad: qué datos se pueden leer en cada distro, coste del muestreo, latencia de la voz | 🚧 En curso |
| 1 | MVP: recolector, eventos, base curada, puntuación, voz con Piper, consola | Planificada |
| 2 | Registro en SQLite, informe HTML/PDF, niveles de detalle, explicaciones por metadatos | Planificada |
| 3 | Componente con privilegios mínimos, journald, modo juego, pruebas en varias distros | Planificada |
| 4 | Repositorio APT firmado, paquete `.deb`, pruebas con usuarios | Planificada |

Plataformas objetivo: Ubuntu 24.04 y 22.04, y Debian 12, con GNOME o KDE (Wayland o X11).

## Desarrollo

El código que lee el estado de Linux recibe como parámetros sus raíces (`/proc`, `/sys`)
y la forma de ejecutar comandos. Así se puede probar contra un `/proc` falso en cualquier
sistema operativo, incluido macOS.

```bash
python3 -m venv .venv && .venv/bin/pip install pytest psutil
.venv/bin/pytest
```

```
src/ecoprocesos/probe/   Sondeo de la Fase 0: capacidades, coste del muestreo, informe, CLI
tests/                   Pruebas con pytest y el fixture FakeProc (un árbol /proc falso)
```

El comportamiento nuevo se desarrolla con las pruebas primero (TDD).
