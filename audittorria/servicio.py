"""Orquesta la ejecución completa de una auditoría.

Este módulo actúa como punto central entre la interfaz de entrada, el motor de
auditoría de red o local y la generación del PDF final, manteniendo ese flujo
desacoplado del resto de capas.
"""

from __future__ import annotations

from .auditoria import auditar_objetivos
from .auditoria_local import auditar_equipo_local
from .informes import generar_pdf
from .modelos import NotificadorProgreso, ParametrosAuditoria, ProgresoAuditoria, ResumenAuditoria


# --------------------------------------------------------------------------------------
# Servicio de alto nivel que orquesta auditoría y generación del informe.
# --------------------------------------------------------------------------------------


def ejecutar_auditoria_completa(
    parametros: ParametrosAuditoria,
    notificar_progreso: NotificadorProgreso | None = None,
) -> ResumenAuditoria:
    """Ejecuta la auditoría y crea el PDF final devolviendo el resumen resultante."""
    if parametros.modo_auditoria == "local":
        resumen = auditar_equipo_local(parametros, notificar_progreso=notificar_progreso)
    else:
        resumen = auditar_objetivos(parametros, notificar_progreso=notificar_progreso)

    generar_pdf(resumen)

    if notificar_progreso is not None and resumen.resultados:
        mensaje_final = (
            f"1/1 - {resumen.resultados[0].ip} -> auditoría local completada"
            if parametros.modo_auditoria == "local"
            else f"{len(resumen.resultados)}/{len(resumen.resultados)} - informe PDF generado"
        )
        notificar_progreso(
            ProgresoAuditoria(
                completados=1 if parametros.modo_auditoria == "local" else len(resumen.resultados),
                total=1 if parametros.modo_auditoria == "local" else len(resumen.resultados),
                porcentaje=100.0,
                mensaje=mensaje_final,
                resultado_equipo=resumen.resultados[0] if parametros.modo_auditoria == "local" else None,
            )
        )

    return resumen
