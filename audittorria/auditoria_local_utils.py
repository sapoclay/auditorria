"""Utilidades compartidas para la auditoría local del equipo."""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from pathlib import Path


SEPARADOR_SEVERIDAD = "["


def ejecutar_comando_seguro(comando: list[str], timeout: int = 10) -> tuple[int | None, str]:
    """Ejecuta un comando del sistema y devuelve el código y la salida sin lanzar excepciones."""
    try:
        proceso = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        salida = (proceso.stdout or "") + ("\n" + proceso.stderr if proceso.stderr else "")
        return proceso.returncode, salida.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, str(error)


def obtener_ip_principal_local() -> str:
    """Intenta descubrir la IP principal del equipo sin necesidad de tráfico real persistente."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_udp:
            socket_udp.connect(("8.8.8.8", 80))
            return socket_udp.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def obtener_ips_locales() -> list[str]:
    """Devuelve las direcciones IP asociadas al equipo local."""
    direcciones: set[str] = {"127.0.0.1"}
    nombre = socket.gethostname()

    try:
        for informacion in socket.getaddrinfo(nombre, None):
            direccion = informacion[4][0]
            try:
                direcciones.add(str(ipaddress.ip_address(direccion)))
            except ValueError:
                continue
    except OSError:
        pass

    direcciones.add(obtener_ip_principal_local())
    return sorted(direcciones, key=lambda ip: int(ipaddress.ip_address(ip)))


def resumir_lineas(texto: str, max_lineas: int = 8) -> list[str]:
    """Recorta la salida de comandos largos para que el informe siga siendo legible."""
    lineas = [linea.strip() for linea in texto.splitlines() if linea.strip()]
    if len(lineas) <= max_lineas:
        return lineas
    return lineas[:max_lineas]


def leer_archivo_texto(ruta: Path) -> str:
    """Lee un archivo de texto de forma segura devolviendo cadena vacía si no es accesible."""
    try:
        return ruta.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def obtener_valor_configuracion(texto: str, clave: str) -> str | None:
    """Extrae el último valor efectivo de una clave sencilla en ficheros de configuración."""
    valor_encontrado: str | None = None
    for linea in texto.splitlines():
        linea_limpia = linea.split("#", 1)[0].strip()
        if not linea_limpia:
            continue
        partes = linea_limpia.split()
        if len(partes) >= 2 and partes[0].lower() == clave.lower():
            valor_encontrado = " ".join(partes[1:])
    return valor_encontrado


def extraer_version_desde_texto_local(texto: str) -> str | None:
    """Localiza un número de versión razonable en una salida de comando o metadato local."""
    patrones = [
        r"\b\d+(?:\.\d+){1,4}(?:[A-Za-z0-9._\-+~:]*)\b",
        r"\b\d+\.\d+p\d+\b",
    ]
    for patron in patrones:
        coincidencia = re.search(patron, texto)
        if coincidencia:
            return coincidencia.group(0)
    return None


def obtener_version_desde_comandos(comandos: list[list[str]]) -> tuple[str | None, str | None]:
    """Ejecuta varios comandos candidatos y devuelve la primera versión válida detectada."""
    for comando in comandos:
        ejecutable = comando[0]
        if shutil.which(ejecutable) is None:
            continue
        _codigo, salida = ejecutar_comando_seguro(comando, timeout=15)
        if not salida.strip():
            continue
        version = extraer_version_desde_texto_local(salida)
        if version:
            return version, "Comando local: " + " ".join(comando)
    return None, None


def obtener_version_paquete_linux(paquetes: list[str]) -> tuple[str | None, str | None]:
    """Consulta la versión instalada de un paquete Linux usando dpkg o rpm cuando están disponibles."""
    for paquete in paquetes:
        if shutil.which("dpkg-query"):
            codigo, salida = ejecutar_comando_seguro(["dpkg-query", "-W", "-f=${Version}", paquete], timeout=10)
            if codigo == 0 and salida.strip() and "no packages found" not in salida.lower():
                return salida.strip(), f"Paquete instalado: {paquete}"

        if shutil.which("rpm"):
            codigo, salida = ejecutar_comando_seguro(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", paquete], timeout=10)
            if codigo == 0 and salida.strip() and "not installed" not in salida.lower():
                return salida.strip(), f"Paquete instalado: {paquete}"

    return None, None


def obtener_estado_servicio_linux(servicios: list[str]) -> str | None:
    """Intenta determinar si un servicio Linux está activo para usarlo como evidencia adicional."""
    if not shutil.which("systemctl"):
        return None
    for servicio in servicios:
        codigo, salida = ejecutar_comando_seguro(["systemctl", "is-active", servicio], timeout=10)
        if codigo == 0 and salida.strip():
            return f"Servicio {servicio}: {salida.strip()}"
    return None