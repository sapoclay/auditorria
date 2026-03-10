from __future__ import annotations

import ipaddress
from datetime import datetime
from pathlib import Path

from .configuracion import CARPETA_REPORTES, MAXIMO_HOSTS_RED, PUERTOS_COMUNES


# --------------------------------------------------------------------------------------
# Funciones de validación y transformación de datos de entrada.
# --------------------------------------------------------------------------------------


def normalizar_red_para_auditoria(red_texto: str) -> str:
    """Acepta una red CIDR o una IP base y devuelve un rango usable para la auditoría."""
    red_limpia = red_texto.strip()
    if not red_limpia:
        raise ValueError("Debe indicar una red o una IP base.")

    if "/" in red_limpia:
        return red_limpia

    try:
        direccion = ipaddress.ip_address(red_limpia)
    except ValueError as error:
        raise ValueError(f"La red indicada no es válida: {error}") from error

    if direccion.version == 4:
        octetos = red_limpia.split(".")
        if octetos[1] == "0" and octetos[2] == "0" and octetos[3] == "0":
            return f"{red_limpia}/8"
        if octetos[2] == "0" and octetos[3] == "0":
            return f"{red_limpia}/16"
        if octetos[3] == "0":
            return f"{red_limpia}/24"
        return f"{red_limpia}/32"

    return f"{red_limpia}/128"


def obtener_objetivos_desde_red(red_texto: str) -> list[str]:
    """Convierte una red CIDR en una lista de IPs utilizables para auditar."""
    try:
        red = ipaddress.ip_network(normalizar_red_para_auditoria(red_texto), strict=False)
    except ValueError as error:
        raise ValueError(f"La red indicada no es válida: {error}") from error

    objetivos = [str(host) for host in red.hosts()]

    if not objetivos:
        raise ValueError("La red indicada no contiene hosts auditables.")

    if len(objetivos) > MAXIMO_HOSTS_RED:
        raise ValueError(
            f"La red contiene {len(objetivos)} hosts. Reduzca el rango para no superar {MAXIMO_HOSTS_RED} hosts."
        )

    return objetivos



def obtener_objetivos_desde_ips(ips_texto: str) -> list[str]:
    """Valida una lista de IPs separadas por comas y la normaliza."""
    if not ips_texto.strip():
        raise ValueError("Debe indicar al menos una dirección IP.")

    objetivos: list[str] = []
    for fragmento in ips_texto.split(","):
        direccion = fragmento.strip()
        if not direccion:
            continue
        try:
            objetivos.append(str(ipaddress.ip_address(direccion)))
        except ValueError as error:
            raise ValueError(f"La IP '{direccion}' no es válida.") from error

    if not objetivos:
        raise ValueError("No se han encontrado IPs válidas para auditar.")

    return objetivos



def validar_puerto(puerto: int) -> None:
    """Comprueba que un puerto pertenezca al rango permitido 1-65535."""
    if puerto < 1 or puerto > 65535:
        raise ValueError(f"El puerto {puerto} está fuera del rango válido 1-65535.")



def obtener_puertos(puertos_texto: str | None) -> list[int]:
    """Interpreta puertos individuales y rangos para obtener una lista ordenada."""
    if not puertos_texto:
        return sorted(PUERTOS_COMUNES)

    puertos: set[int] = set()

    for fragmento in puertos_texto.split(","):
        parte = fragmento.strip()
        if not parte:
            continue

        if "-" in parte:
            inicio_texto, fin_texto = parte.split("-", 1)
            inicio = int(inicio_texto)
            fin = int(fin_texto)
            if inicio > fin:
                raise ValueError(f"El rango '{parte}' es inválido.")
            for puerto in range(inicio, fin + 1):
                validar_puerto(puerto)
                puertos.add(puerto)
        else:
            puerto = int(parte)
            validar_puerto(puerto)
            puertos.add(puerto)

    if not puertos:
        raise ValueError("No se pudo obtener ningún puerto válido.")

    return sorted(puertos)



def construir_ruta_pdf(ruta_salida: str | None) -> Path:
    """Prepara la ruta del informe PDF y crea la carpeta de salida cuando sea necesario."""
    if ruta_salida:
        ruta_pdf = Path(ruta_salida).expanduser().resolve()
        ruta_pdf.parent.mkdir(parents=True, exist_ok=True)
        return ruta_pdf

    carpeta_reportes = CARPETA_REPORTES.resolve()
    carpeta_reportes.mkdir(parents=True, exist_ok=True)
    marca_tiempo = datetime.now().strftime("%Y%m%d_%H%M%S")
    return carpeta_reportes / f"auditoria_{marca_tiempo}.pdf"



def ordenar_ips(objetivos: list[str]) -> list[str]:
    """Ordena IPs IPv4 e IPv6 de forma consistente para mejorar la lectura del informe."""
    return sorted(objetivos, key=lambda ip: int(ipaddress.ip_address(ip)))
