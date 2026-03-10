"""Orquesta la ejecución completa de una auditoría.

Este módulo actúa como punto central entre la interfaz de entrada, el motor de
auditoría de red o local y la generación del PDF final, manteniendo ese flujo
desacoplado del resto de capas.
"""

from __future__ import annotations

from .auditoria import auditar_objetivos
from .auditoria_local import auditar_equipo_local
from .informes import generar_pdf
from .modelos import NotificadorProgreso, ParametrosAuditoria, ResumenAuditoria


# --------------------------------------------------------------------------------------
# Servicio de alto nivel que orquesta auditoría y generación del informe.
# --------------------------------------------------------------------------------------


def ejecutar_auditoria_completa(
    parametros: ParametrosAuditoria,
    notificar_progreso: NotificadorProgreso | None = None,
) -> ResumenAuditoria:
    """Ejecuta la auditoría y crea el PDF final devolviendo el resumen resultante."""
    if parametros.modo_auditoria == "local":
        resumen = auditar_equipo_local(parametros)
        if notificar_progreso is not None:
            from .modelos import ProgresoAuditoria

            notificar_progreso(
                ProgresoAuditoria(
                    completados=1,
                    total=1,
                    porcentaje=100.0,
                    mensaje=f"1/1 - {resumen.resultados[0].ip} -> auditoría local completada",
                    resultado_equipo=resumen.resultados[0],
                )
            )
    else:
        resumen = auditar_objetivos(parametros, notificar_progreso=notificar_progreso)
    generar_pdf(resumen)
    return resumen
