"""Coordina el arranque de AudiTorría.

Este módulo decide si la aplicación debe ejecutarse en consola o con interfaz
gráfica. No realiza auditorías por sí mismo: solo interpreta el modo de
entrada y delega en el módulo adecuado.
"""

from __future__ import annotations

import argparse

from .cli import ejecutar_modo_consola
from .interfaz import ejecutar_modo_grafico, hay_entorno_grafico


# --------------------------------------------------------------------------------------
# Punto de entrada unificado para decidir si se usa consola o interfaz gráfica.
# --------------------------------------------------------------------------------------


def construir_analizador_modo() -> argparse.ArgumentParser:
    """Define argumentos mínimos para decidir el modo antes de delegar la ejecución."""
    analizador = argparse.ArgumentParser(add_help=False)
    analizador.add_argument(
        "--modo",
        choices=["auto", "grafico", "consola"],
        default="auto",
        help="Selecciona si la aplicación debe iniciar con interfaz gráfica o consola.",
    )
    return analizador



def ejecutar_aplicacion(argumentos_crudos: list[str] | None = None) -> int:
    """Selecciona el modo de ejecución y reenvía el control al módulo adecuado."""
    analizador = construir_analizador_modo()
    argumentos_modo, argumentos_restantes = analizador.parse_known_args(argumentos_crudos)

    if argumentos_modo.modo == "grafico":
        return ejecutar_modo_grafico()

    if argumentos_modo.modo == "consola":
        return ejecutar_modo_consola(argumentos_restantes)

    # En modo automático se intenta abrir la GUI solo cuando existe entorno gráfico
    # y no se han pasado argumentos propios de la consola.
    if not argumentos_restantes and hay_entorno_grafico():
        return ejecutar_modo_grafico()

    return ejecutar_modo_consola(argumentos_restantes)
