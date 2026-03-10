"""Implementa la auditoría de red sobre equipos remotos.

Este módulo concentra las comprobaciones de conectividad, escaneo de puertos,
lectura de banners, análisis ligero de servicios y consulta de CVEs públicas
para enriquecer el resultado de cada host auditado.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
from typing import Iterable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .configuracion import MAXIMO_CVES_POR_SERVICIO, PUERTOS_COMUNES, TIEMPO_ESPERA_API_CVES, URL_API_CVES
from .modelos import (
    NotificadorProgreso,
    ParametrosAuditoria,
    ProgresoAuditoria,
    ResultadoEquipo,
    ResultadoPuerto,
    ResumenAuditoria,
)


# --------------------------------------------------------------------------------------
# Funciones de comprobación de red.
# --------------------------------------------------------------------------------------


_CACHE_CVES: dict[tuple[str, str], list[tuple[float, str]]] = {}


def ejecutar_ping(ip: str, tiempo_espera_ms: int = 1000) -> tuple[bool, str, str, str]:
    """Lanza un ping para conocer si el equipo responde y recoger datos básicos."""
    sistema = platform.system().lower()
    es_ipv6 = ipaddress.ip_address(ip).version == 6

    # El comando cambia un poco entre Windows y Linux.
    if sistema == "windows":
        comando = ["ping"]
        if es_ipv6:
            comando.append("-6")
        comando.extend(["-n", "1", "-w", str(tiempo_espera_ms), ip])
    else:
        # En Linux el timeout del ping se indica en segundos.
        segundos = max(1, round(tiempo_espera_ms / 1000))
        comando = ["ping"]
        if es_ipv6:
            comando.append("-6")
        comando.extend(["-c", "1", "-W", str(segundos), ip])

    try:
        proceso = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(3, tiempo_espera_ms / 1000 + 2),
        )
    except subprocess.TimeoutExpired:
        return False, "Sin respuesta", "No disponible", "Tiempo de espera agotado"
    except FileNotFoundError:
        return False, "Sin respuesta", "No disponible", "No se encontró el comando ping en el sistema"

    salida = f"{proceso.stdout}\n{proceso.stderr}"
    return proceso.returncode == 0, extraer_tiempo_ping(salida), extraer_ttl(salida), salida.strip()



def extraer_tiempo_ping(salida: str) -> str:
    """Busca el tiempo de respuesta en la salida del comando ping."""
    patrones = [
        r"time[=<]\s*([\d.,]+)\s*ms",
        r"tiempo[=<]\s*([\d.,]+)\s*ms",
        r"time\s*[=<]\s*([\d.,]+)ms",
        r"tiempo\s*[=<]\s*([\d.,]+)ms",
    ]

    for patron in patrones:
        coincidencia = re.search(patron, salida, flags=re.IGNORECASE)
        if coincidencia:
            return f"{coincidencia.group(1).replace(',', '.')} ms"

    return "No disponible"



def extraer_ttl(salida: str) -> str:
    """Localiza el TTL en la salida del ping cuando está disponible."""
    coincidencia = re.search(r"ttl[=:\s]+(\d+)", salida, flags=re.IGNORECASE)
    if coincidencia:
        return coincidencia.group(1)
    return "No disponible"



def clasificar_latencia(tiempo_respuesta_ms: str) -> str:
    """Convierte el tiempo de respuesta en una categoría legible para el informe."""
    coincidencia = re.search(r"([\d.]+)", tiempo_respuesta_ms)
    if not coincidencia:
        return "No disponible"

    tiempo = float(coincidencia.group(1))
    if tiempo < 10:
        return "Excelente"
    if tiempo < 50:
        return "Buena"
    if tiempo < 120:
        return "Media"
    return "Alta"



def estimar_sistema_operativo(ttl: str) -> str:
    """Ofrece una estimación orientativa del sistema operativo a partir del TTL."""
    if not ttl.isdigit():
        return "No determinado"

    ttl_valor = int(ttl)
    if ttl_valor <= 64:
        return "Probablemente Linux/Unix"
    if ttl_valor <= 128:
        return "Probablemente Windows"
    return "Probablemente dispositivo de red/Unix"



def resolver_nombre_host(ip: str) -> str:
    """Intenta resolver el nombre DNS inverso de una IP."""
    try:
        nombre_host, _, _ = socket.gethostbyaddr(ip)
        return nombre_host
    except (socket.herror, socket.gaierror, OSError):
        return "No resuelto"



def leer_banner_generico(ip: str, puerto: int, enviar: bytes | None = None, tiempo_espera: float = 1.2) -> str | None:
    """Obtiene un banner simple de servicios que envían texto al establecer conexión."""
    familia_socket = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    destino = (ip, puerto, 0, 0) if familia_socket == socket.AF_INET6 else (ip, puerto)

    try:
        with socket.socket(familia_socket, socket.SOCK_STREAM) as socket_tcp:
            socket_tcp.settimeout(tiempo_espera)
            socket_tcp.connect(destino)
            if enviar:
                socket_tcp.sendall(enviar)
            datos = socket_tcp.recv(256)
    except OSError:
        return None

    texto = datos.decode("utf-8", errors="replace").strip()
    return texto or None



def obtener_informacion_http(ip: str, puerto: int, usar_tls: bool = False) -> str | None:
    """Realiza una petición HTTP mínima para identificar cabeceras útiles del servicio web."""
    familia_socket = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    destino = (ip, puerto, 0, 0) if familia_socket == socket.AF_INET6 else (ip, puerto)
    solicitud = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("utf-8")

    try:
        with socket.socket(familia_socket, socket.SOCK_STREAM) as socket_tcp:
            socket_tcp.settimeout(2.0)
            socket_tcp.connect(destino)

            if usar_tls:
                contexto = ssl.create_default_context()
                contexto.check_hostname = False
                contexto.verify_mode = ssl.CERT_NONE
                with contexto.wrap_socket(socket_tcp, server_hostname=ip) as socket_seguro:
                    socket_seguro.sendall(solicitud)
                    respuesta = socket_seguro.recv(512).decode("utf-8", errors="replace")
            else:
                socket_tcp.sendall(solicitud)
                respuesta = socket_tcp.recv(512).decode("utf-8", errors="replace")
    except OSError:
        return None

    lineas = [linea.strip() for linea in respuesta.splitlines() if linea.strip()]
    if not lineas:
        return None

    estado = lineas[0]
    cabecera_server = next((linea for linea in lineas if linea.lower().startswith("server:")), "")
    if cabecera_server:
        return f"{estado}; {cabecera_server}"
    return estado



def obtener_informacion_tls(ip: str, puerto: int) -> str | None:
    """Obtiene datos básicos del certificado TLS para enriquecer el análisis del equipo."""
    familia_socket = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    destino = (ip, puerto, 0, 0) if familia_socket == socket.AF_INET6 else (ip, puerto)

    try:
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        with socket.socket(familia_socket, socket.SOCK_STREAM) as socket_tcp:
            socket_tcp.settimeout(3.0)
            socket_tcp.connect(destino)
            with contexto.wrap_socket(socket_tcp, server_hostname=ip) as socket_seguro:
                certificado = socket_seguro.getpeercert()
    except OSError:
        return None

    if not certificado:
        return "TLS detectado, pero no se pudo leer el certificado"

    sujeto = certificado.get("subject", ())
    nombre_comun = "Desconocido"
    for grupo in sujeto:
        for clave, valor in grupo:
            if clave == "commonName":
                nombre_comun = valor
                break

    fecha_expiracion = certificado.get("notAfter")
    if isinstance(fecha_expiracion, str) and fecha_expiracion:
        try:
            expira = datetime.datetime.strptime(fecha_expiracion, "%b %d %H:%M:%S %Y %Z")
            dias_restantes = (expira - datetime.datetime.utcnow()).days
            return f"Certificado TLS CN={nombre_comun}, caduca en {dias_restantes} días"
        except ValueError:
            return f"Certificado TLS CN={nombre_comun}"

    return f"Certificado TLS CN={nombre_comun}"



def realizar_comprobaciones_adicionales(ip: str, puertos_abiertos: list[ResultadoPuerto]) -> list[str]:
    """Ejecuta comprobaciones ligeras adicionales sobre servicios detectados en el equipo."""
    comprobaciones: list[str] = []
    puertos = {puerto.numero for puerto in puertos_abiertos}

    # Solo se intenta leer información extra de los servicios que realmente aparecieron abiertos.
    if 21 in puertos:
        banner_ftp = leer_banner_generico(ip, 21)
        if banner_ftp:
            comprobaciones.append(f"Banner FTP: {banner_ftp}")

    if 22 in puertos:
        banner_ssh = leer_banner_generico(ip, 22)
        if banner_ssh:
            comprobaciones.append(f"Banner SSH: {banner_ssh}")

    if 25 in puertos or 587 in puertos:
        puerto_smtp = 25 if 25 in puertos else 587
        banner_smtp = leer_banner_generico(ip, puerto_smtp)
        if banner_smtp:
            comprobaciones.append(f"Banner SMTP ({puerto_smtp}): {banner_smtp}")

    for puerto_http in [80, 8080]:
        if puerto_http in puertos:
            informacion_http = obtener_informacion_http(ip, puerto_http, usar_tls=False)
            if informacion_http:
                comprobaciones.append(f"HTTP {puerto_http}: {informacion_http}")

    for puerto_https in [443, 8443]:
        if puerto_https in puertos:
            informacion_http = obtener_informacion_http(ip, puerto_https, usar_tls=True)
            if informacion_http:
                comprobaciones.append(f"HTTPS {puerto_https}: {informacion_http}")
            informacion_tls = obtener_informacion_tls(ip, puerto_https)
            if informacion_tls:
                comprobaciones.append(f"TLS {puerto_https}: {informacion_tls}")

    return comprobaciones



def extraer_versiones_servicios(comprobaciones: list[str]) -> list[tuple[str, str, str]]:
    """Intenta identificar producto, versión exacta y origen a partir de banners y cabeceras."""
    # Cada patrón intenta reconocer un programa y su versión dentro del texto recogido.
    patrones = [
        ("OpenSSH", re.compile(r"OpenSSH[_/ -](?P<version>[0-9][A-Za-z0-9._\-p]+)", re.IGNORECASE)),
        ("vsFTPd", re.compile(r"vsFTPd\s+(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("ProFTPD", re.compile(r"ProFTPD(?:\s+Server)?\s+(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Pure-FTPd", re.compile(r"Pure-FTPd\s+(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Apache HTTP Server", re.compile(r"server:\s*Apache/?(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("nginx", re.compile(r"server:\s*nginx/?(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Microsoft IIS", re.compile(r"server:\s*Microsoft-IIS/?(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("OpenResty", re.compile(r"server:\s*openresty/?(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Caddy", re.compile(r"server:\s*caddy/?(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Postfix", re.compile(r"Postfix(?:\s|/|-)(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Exim", re.compile(r"Exim(?:\s|/|-)(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
        ("Redis", re.compile(r"redis[^\n]*\bv=(?P<version>[0-9][A-Za-z0-9._\-]+)", re.IGNORECASE)),
    ]

    versiones_detectadas: list[tuple[str, str, str]] = []
    firmas_unicas: set[tuple[str, str]] = set()

    for comprobacion in comprobaciones:
        # Se revisa cada texto recogido hasta encontrar una versión reconocible.
        for producto, patron in patrones:
            coincidencia = patron.search(comprobacion)
            if not coincidencia:
                continue
            version = coincidencia.group("version")
            firma = (producto.lower(), version.lower())
            if firma in firmas_unicas:
                continue
            firmas_unicas.add(firma)
            versiones_detectadas.append((producto, version, comprobacion))

    return versiones_detectadas



def normalizar_version(version: str) -> str:
    """Obtiene una versión simplificada para mejorar la comparación con referencias CVE."""
    coincidencia = re.search(r"\d+(?:\.\d+)+", version)
    return coincidencia.group(0) if coincidencia else version



def clasificar_severidad_cvss(puntuacion: float) -> str:
    """Convierte una puntuación CVSS en una severidad textual legible."""
    if puntuacion >= 9.0:
        return "CRITICO"
    if puntuacion >= 7.0:
        return "ALTO"
    if puntuacion >= 4.0:
        return "MEDIO"
    if puntuacion > 0:
        return "BAJO"
    return "DESCONOCIDA"



def traducir_severidad_cvss(severidad: str) -> str:
    """Normaliza la severidad CVSS a etiquetas en español."""
    equivalencias = {
        "CRITICAL": "CRITICO",
        "HIGH": "ALTO",
        "MEDIUM": "MEDIO",
        "LOW": "BAJO",
        "NONE": "DESCONOCIDA",
    }
    return equivalencias.get(severidad.upper(), severidad.upper())



def extraer_metricas_cve(registro_cve: dict) -> tuple[float, str]:
    """Extrae la puntuación CVSS y severidad desde distintas versiones de métricas NVD."""
    metricas = registro_cve.get("metrics", {})
    for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if clave not in metricas or not metricas[clave]:
            continue
        metrica = metricas[clave][0]
        datos_cvss = metrica.get("cvssData", {})
        puntuacion = float(datos_cvss.get("baseScore", 0.0) or 0.0)
        severidad = str(datos_cvss.get("baseSeverity") or metrica.get("baseSeverity") or clasificar_severidad_cvss(puntuacion))
        return puntuacion, traducir_severidad_cvss(severidad)
    return 0.0, "DESCONOCIDA"



def consultar_cves_producto(producto: str, version: str) -> list[tuple[float, str]]:
    """Consulta una base pública de CVEs y prioriza las coincidencias por severidad CVSS."""
    clave_cache = (producto.lower(), version.lower())
    # Si ya se consultó antes lo mismo, se reutiliza el resultado guardado.
    if clave_cache in _CACHE_CVES:
        return _CACHE_CVES[clave_cache]

    version_normalizada = normalizar_version(version)
    consulta = f"{producto} {version_normalizada}"
    parametros = urlencode({"keywordSearch": consulta, "resultsPerPage": MAXIMO_CVES_POR_SERVICIO})
    solicitud = Request(
        f"{URL_API_CVES}?{parametros}",
        headers={"User-Agent": "AudiTorria/1.0"},
    )

    try:
        with urlopen(solicitud, timeout=TIEMPO_ESPERA_API_CVES) as respuesta:
            datos = json.loads(respuesta.read().decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        _CACHE_CVES[clave_cache] = []
        return []

    version_normalizada = version_normalizada.lower()
    resultados: list[tuple[float, str]] = []
    vistos: set[str] = set()

    for entrada in datos.get("vulnerabilities", []):
        # Se filtran solo las entradas que parecen hablar de ese producto y esa versión.
        cve = entrada.get("cve", {})
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id or cve_id in vistos:
            continue

        descripcion = next(
            (
                item.get("value", "")
                for item in cve.get("descriptions", [])
                if item.get("lang") == "en"
            ),
            "",
        )
        texto_contexto = f"{descripcion}\n{json.dumps(cve.get('configurations', []), ensure_ascii=False)}".lower()
        if producto.lower() not in texto_contexto:
            continue
        if version.lower() not in texto_contexto and version_normalizada not in texto_contexto:
            continue

        puntuacion, severidad = extraer_metricas_cve(cve)
        descripcion_corta = descripcion.strip().replace("\n", " ")
        if len(descripcion_corta) > 220:
            descripcion_corta = descripcion_corta[:217].rstrip() + "..."
        resultados.append(
            (
                puntuacion,
                f"[{severidad}][CVSS {puntuacion:.1f}] {cve_id} - {producto} {version}: {descripcion_corta}",
            )
        )
        vistos.add(cve_id)

    resultados.sort(key=lambda dato: dato[0], reverse=True)
    _CACHE_CVES[clave_cache] = resultados[:MAXIMO_CVES_POR_SERVICIO]
    return _CACHE_CVES[clave_cache]



def analizar_versiones_y_cves(resultado: ResultadoEquipo) -> None:
    """Extrae versiones exactas de servicios y consulta vulnerabilidades CVE relacionadas."""
    # Primero se intenta sacar versiones desde banners y cabeceras ya recogidos.
    versiones_detectadas = extraer_versiones_servicios(resultado.comprobaciones_adicionales)
    if not versiones_detectadas:
        return

    resultado.versiones_servicios = [
        f"{producto} {version} | Evidencia: {origen}"
        for producto, version, origen in versiones_detectadas
    ]

    vulnerabilidades: list[tuple[float, str]] = []
    vistos: set[str] = set()
    for producto, version, _origen in versiones_detectadas[:4]:
        # Se limita el número de consultas para no hacer la revisión demasiado lenta.
        for puntuacion, descripcion in consultar_cves_producto(producto, version):
            if descripcion in vistos:
                continue
            vistos.add(descripcion)
            vulnerabilidades.append((puntuacion, descripcion))

    vulnerabilidades.sort(key=lambda dato: dato[0], reverse=True)
    resultado.vulnerabilidades_cve = [descripcion for _, descripcion in vulnerabilidades[:12]]

    if not resultado.vulnerabilidades_cve:
        return

    # Se deja un resumen corto según el nivel más alto encontrado.
    maxima = vulnerabilidades[0][0]
    if maxima >= 9.0:
        resultado.observaciones_seguridad.append("Se detectaron CVEs críticos asociados a versiones exactas de servicios expuestos.")
    elif maxima >= 7.0:
        resultado.observaciones_seguridad.append("Se detectaron CVEs de severidad alta asociados a versiones exactas de servicios expuestos.")
    else:
        resultado.observaciones_seguridad.append("Se detectaron CVEs asociados a versiones exactas de algunos servicios expuestos.")



def comprobar_puerto(ip: str, puerto: int, tiempo_espera: float = 0.5) -> ResultadoPuerto | None:
    """Prueba una conexión TCP breve para detectar si un puerto está accesible."""
    familia_socket = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    destino = (ip, puerto, 0, 0) if familia_socket == socket.AF_INET6 else (ip, puerto)

    try:
        with socket.socket(familia_socket, socket.SOCK_STREAM) as socket_tcp:
            socket_tcp.settimeout(tiempo_espera)
            estado = socket_tcp.connect_ex(destino)
    except OSError:
        return None

    if estado == 0:
        return ResultadoPuerto(
            numero=puerto,
            servicio=PUERTOS_COMUNES.get(puerto, "Servicio no identificado"),
            estado="Abierto",
        )

    return None



def escanear_puertos(ip: str, puertos: Iterable[int], concurrencia: int) -> list[ResultadoPuerto]:
    """Revisa varios puertos en paralelo para reducir el tiempo de espera."""
    resultados: list[ResultadoPuerto] = []

    # Se prueban varios puertos a la vez para tardar menos en cada equipo.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrencia)) as ejecutor:
        futuros = [ejecutor.submit(comprobar_puerto, ip, puerto) for puerto in puertos]
        for futuro in concurrent.futures.as_completed(futuros):
            resultado = futuro.result()
            if resultado is not None:
                resultados.append(resultado)

    return sorted(resultados, key=lambda dato: dato.numero)



def analizar_seguridad(resultado: ResultadoEquipo) -> list[str]:
    """Genera observaciones de seguridad básicas a partir de los servicios detectados."""
    observaciones: list[str] = []
    puertos_abiertos = {puerto.numero for puerto in resultado.puertos_abiertos}

    # Estas observaciones son orientativas y sirven como resumen rápido.
    if not resultado.activo:
        observaciones.append("El equipo no respondió al ping. Puede estar apagado, filtrado o bloquear ICMP.")

    if not resultado.puertos_abiertos:
        observaciones.append("No se detectaron puertos abiertos dentro de la lista auditada.")
    else:
        observaciones.append(
            f"Se detectaron {len(resultado.puertos_abiertos)} puertos abiertos en la lista auditada."
        )

    if 21 in puertos_abiertos:
        observaciones.append("FTP abierto: conviene migrar a SFTP o FTPS para evitar credenciales en texto claro.")
    if 23 in puertos_abiertos:
        observaciones.append("Telnet abierto: es recomendable deshabilitarlo y usar SSH.")
    if 80 in puertos_abiertos and 443 not in puertos_abiertos:
        observaciones.append("HTTP expuesto sin HTTPS en el conjunto auditado: revise cifrado y redirecciones seguras.")
    if 445 in puertos_abiertos:
        observaciones.append("SMB expuesto: limite el acceso por red y verifique versiones y parches.")
    if 3389 in puertos_abiertos:
        observaciones.append("RDP abierto: restrinja origen, active MFA y revise políticas de bloqueo.")
    if 22 in puertos_abiertos:
        observaciones.append("SSH abierto: revise contraseñas, claves, listas de acceso y versiones soportadas.")
    if 3306 in puertos_abiertos or 5432 in puertos_abiertos or 1433 in puertos_abiertos:
        observaciones.append("Base de datos accesible por red: confirme segmentación, cifrado y control de acceso.")
    if resultado.ttl != "No disponible":
        observaciones.append(
            f"TTL observado: {resultado.ttl}. Sirve solo como referencia orientativa y no garantiza el sistema operativo."
        )

    return observaciones



def auditar_equipo(ip: str, puertos: list[int], concurrencia_puertos: int) -> ResultadoEquipo:
    """Realiza todas las comprobaciones necesarias sobre un único equipo."""
    resultado = ResultadoEquipo(ip=ip)

    try:
        # Primero se recoge la información más básica del equipo.
        activo, tiempo_respuesta, ttl, detalle_ping = ejecutar_ping(ip)
        resultado.activo = activo
        resultado.tiempo_respuesta_ms = tiempo_respuesta
        resultado.categoria_latencia = clasificar_latencia(tiempo_respuesta)
        resultado.ttl = ttl
        resultado.sistema_operativo_probable = estimar_sistema_operativo(ttl)
        resultado.nombre_host = resolver_nombre_host(ip)

        # Aunque el ping falle, se siguen revisando puertos por si el equipo solo bloquea ICMP.
        resultado.puertos_abiertos = escanear_puertos(ip, puertos, concurrencia_puertos)
        resultado.comprobaciones_adicionales = realizar_comprobaciones_adicionales(ip, resultado.puertos_abiertos)
        analizar_versiones_y_cves(resultado)
        resultado.observaciones_seguridad.extend(analizar_seguridad(resultado))

        # Si no hubo respuesta ni puertos abiertos, se guarda el detalle del ping fallido.
        if not activo and not resultado.puertos_abiertos:
            resultado.error = detalle_ping
    except Exception as error:  # noqa: BLE001
        resultado.error = f"Error durante la auditoría: {error}"
        resultado.observaciones_seguridad.append("No fue posible completar todas las comprobaciones del equipo.")

    return resultado



def auditar_objetivos(
    parametros: ParametrosAuditoria,
    notificar_progreso: NotificadorProgreso | None = None,
) -> ResumenAuditoria:
    """Ejecuta la auditoría completa de todos los equipos definidos por el usuario."""
    resultados: list[ResultadoEquipo] = []

    # Cada equipo se revisa en paralelo para acelerar redes con varios objetivos.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, parametros.concurrencia)) as ejecutor:
        futuros = {
            ejecutor.submit(
                auditar_equipo,
                ip,
                parametros.puertos,
                min(16, max(1, len(parametros.puertos))),
            ): ip
            for ip in parametros.objetivos
        }

        for indice, futuro in enumerate(concurrent.futures.as_completed(futuros), start=1):
            # Cada vez que termina un equipo, se guarda y se notifica el avance.
            resultado = futuro.result()
            resultados.append(resultado)

            if notificar_progreso is not None:
                porcentaje = (indice / len(parametros.objetivos)) * 100 if parametros.objetivos else 100.0
                notificar_progreso(
                    ProgresoAuditoria(
                        completados=indice,
                        total=len(parametros.objetivos),
                        porcentaje=porcentaje,
                        mensaje=(
                            f"{indice}/{len(parametros.objetivos)} - {resultado.ip} -> "
                            f"{'activo' if resultado.activo else 'sin ping'} / {len(resultado.puertos_abiertos)} puertos abiertos"
                        ),
                        resultado_equipo=resultado,
                    )
                )

    # Al final se ordenan las IPs para que el informe quede más claro de leer.
    resultados_ordenados = sorted(resultados, key=lambda equipo: int(ipaddress.ip_address(equipo.ip)))
    return ResumenAuditoria(parametros=parametros, resultados=resultados_ordenados)
