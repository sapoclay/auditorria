from __future__ import annotations

import argparse
import platform

from .configuracion import NOMBRE_APLICACION
from .modelos import ParametrosAuditoria
from .servicio import ejecutar_auditoria_completa
from .utilidades import (
    construir_ruta_pdf,
    normalizar_red_para_auditoria,
    obtener_objetivos_desde_ips,
    obtener_objetivos_desde_red,
    obtener_puertos,
)


# --------------------------------------------------------------------------------------
# Interfaz de línea de comandos.
# --------------------------------------------------------------------------------------


def mostrar_banner() -> None:
    """Muestra un encabezado simple para identificar la aplicación en consola."""
    print(
        f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                {NOMBRE_APLICACION:<37}║
║                  Auditoría básica de red y seguridad                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
Uso previsto: auditorías autorizadas sobre equipos propios o con permiso.
"""
    )



def construir_analizador_argumentos() -> argparse.ArgumentParser:
    """Define los argumentos de la versión en consola."""
    analizador = argparse.ArgumentParser(
        description="Audita una red, una lista de direcciones IP o el equipo local y genera un informe en PDF.",
    )
    analizador.add_argument(
        "--red",
        help="Red a revisar. Puede escribir 192.168.1.0/24 o solo 192.168.1.0 para que se interprete como /24.",
    )
    analizador.add_argument("--ips", help="Lista de IPs separadas por comas. Ejemplo: 192.168.1.10,192.168.1.20")
    analizador.add_argument("--local", action="store_true", help="Realiza una auditoría local avanzada del equipo actual")
    analizador.add_argument("--puertos", help="Puertos o rangos separados por comas. Ejemplo: 22,80,443,8000-8010")
    analizador.add_argument(
        "--salida",
        help="Ruta del PDF de salida. Si no se indica, se crea automáticamente en la carpeta reportes.",
    )
    analizador.add_argument(
        "--concurrencia",
        type=int,
        default=32,
        help="Número máximo de comprobaciones paralelas. Valor por defecto: 32",
    )
    return analizador



def solicitar_objetivos_interactivos() -> tuple[list[str], str]:
    """Pide por consola una red o varias IPs cuando no se suministran argumentos."""
    print("Seleccione el tipo de auditoría:")
    print("  1. Auditar una red")
    print("  2. Auditar una o varias IPs")
    print("  3. Auditar el equipo local")

    while True:
        opcion = input("Opción [1/2]: ").strip()
        if opcion == "1":
            red = input("Introduzca la red (por ejemplo 192.168.1.0 o 192.168.1.0/24): ").strip()
            red_normalizada = normalizar_red_para_auditoria(red)
            return obtener_objetivos_desde_red(red), f"Red auditada: {red_normalizada}"
        if opcion == "2":
            ips = input("Introduzca una o varias IPs separadas por comas: ").strip()
            objetivos = obtener_objetivos_desde_ips(ips)
            return objetivos, f"IPs auditadas: {', '.join(objetivos)}"
        if opcion == "3":
            return ["127.0.0.1"], "Equipo local auditado"
        print("[!] Opción no válida. Inténtelo de nuevo.")



def obtener_objetivos_y_descripcion(argumentos: argparse.Namespace) -> tuple[list[str], str]:
    """Decide de dónde provienen los objetivos definidos por el usuario."""
    cantidad_modos = sum(1 for valor in [bool(argumentos.red), bool(argumentos.ips), bool(argumentos.local)] if valor)
    if cantidad_modos > 1:
        raise ValueError("No puede combinar --red, --ips y --local al mismo tiempo.")
    if argumentos.local:
        return ["127.0.0.1"], "Equipo local auditado"
    if argumentos.red:
        red_normalizada = normalizar_red_para_auditoria(argumentos.red)
        return obtener_objetivos_desde_red(argumentos.red), f"Red auditada: {red_normalizada}"
    if argumentos.ips:
        objetivos = obtener_objetivos_desde_ips(argumentos.ips)
        return objetivos, f"IPs auditadas: {', '.join(objetivos)}"
    return solicitar_objetivos_interactivos()



def construir_parametros_desde_argumentos(argumentos: argparse.Namespace) -> ParametrosAuditoria:
    """Convierte la entrada de consola a un objeto reutilizable por el servicio."""
    objetivos, descripcion_objetivo = obtener_objetivos_y_descripcion(argumentos)
    return ParametrosAuditoria(
        objetivos=objetivos,
        descripcion_objetivo=descripcion_objetivo,
        puertos=obtener_puertos(argumentos.puertos),
        ruta_pdf=construir_ruta_pdf(argumentos.salida),
        concurrencia=max(1, argumentos.concurrencia),
        modo_auditoria="local" if argumentos.local else "red",
    )



def ejecutar_modo_consola(argumentos_crudos: list[str] | None = None) -> int:
    """Ejecuta la auditoría en consola y escribe el progreso en pantalla."""
    mostrar_banner()
    analizador = construir_analizador_argumentos()
    argumentos = analizador.parse_args(argumentos_crudos)

    try:
        parametros = construir_parametros_desde_argumentos(argumentos)
        print(f"[OK] Objetivos a auditar: {len(parametros.objetivos)}")
        if parametros.modo_auditoria != "local":
            print(f"[OK] Puertos a revisar: {', '.join(str(puerto) for puerto in parametros.puertos)}")
        else:
            print("[OK] Modo seleccionado: auditoría local avanzada")
        print(f"[OK] Sistema operativo detectado: {platform.system()}")
        print("[OK] Iniciando auditoría...\n")

        resumen = ejecutar_auditoria_completa(
            parametros,
            notificar_progreso=lambda progreso: print(
                f"[OK] {progreso.mensaje} ({progreso.porcentaje:.0f}%)"
            ),
        )

        print("\n[OK] Auditoría finalizada correctamente")
        print(f"[OK] Informe PDF generado en: {resumen.parametros.ruta_pdf}")
        return 0
    except KeyboardInterrupt:
        print("\n[OK] Auditoría cancelada por el usuario")
        return 0
    except Exception as error:  # noqa: BLE001
        print(f"[!] Error: {error}")
        return 1
