"""Implementa la auditoría local del equipo anfitrión.

Aquí se agrupan las comprobaciones no intrusivas que se hacen sobre el propio
sistema: puertos en escucha, firewall, actualizaciones, endurecimiento,
usuarios, servicios y versiones instaladas con posible cruce contra CVEs.
"""

from __future__ import annotations

import getpass
import os
import platform
import re
import shutil
import socket
from pathlib import Path

from .auditoria import consultar_cves_producto
from .auditoria_local_linux import (
    comprobar_permisos_sensibles_linux,
    detectar_puertos_escucha_locales_linux,
    obtener_endurecimiento_linux,
    obtener_politica_contrasenas_linux,
    obtener_resumen_actualizaciones_linux,
    obtener_resumen_antivirus_linux,
    obtener_resumen_comparticiones_linux,
    obtener_resumen_firewall_linux,
    obtener_resumen_servicios_linux,
    obtener_resumen_ssh_y_acceso_remoto_linux,
    obtener_resumen_tareas_programadas_linux,
    obtener_versiones_instaladas_servicios_linux,
)
from .auditoria_local_utils import (
    ejecutar_comando_seguro,
    obtener_ip_principal_local,
    obtener_ips_locales,
    resumir_lineas,
)
from .auditoria_local_windows import obtener_controles_windows_avanzados, obtener_endurecimiento_windows
from .configuracion import PUERTOS_COMUNES
from .modelos import NotificadorProgreso, ParametrosAuditoria, ProgresoAuditoria, ResultadoEquipo, ResultadoPuerto, ResumenAuditoria


# --------------------------------------------------------------------------------------
# Auditoría local del equipo: obtiene datos del propio host con comprobaciones no intrusivas.
# --------------------------------------------------------------------------------------


def obtener_versiones_instaladas_servicios_windows() -> list[tuple[str, str, str]]:
    """Detecta versiones reales de algunos servicios comunes en Windows usando servicio y versión de archivo."""
    if not shutil.which("powershell"):
        return []

    script = (
        "$candidatos = @("
        "  @{ Producto='OpenSSH'; Patron='^sshd$|OpenSSH' },"
        "  @{ Producto='Apache HTTP Server'; Patron='Apache' },"
        "  @{ Producto='nginx'; Patron='nginx' },"
        "  @{ Producto='MySQL'; Patron='MySQL|MySQL80|MariaDB' },"
        "  @{ Producto='PostgreSQL'; Patron='PostgreSQL' },"
        "  @{ Producto='Redis'; Patron='Redis' },"
        "  @{ Producto='Microsoft SQL Server'; Patron='MSSQLSERVER|SQL Server' },"
        "  @{ Producto='IIS'; Patron='W3SVC|World Wide Web Publishing Service' }"
        "); "
        "foreach ($c in $candidatos) { "
        "  $servicio = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $c.Patron -or $_.DisplayName -match $c.Patron } | Select-Object -First 1; "
        "  if ($servicio) { "
        "    $ruta = $servicio.PathName -replace '^\"','' -replace '\".*$',''; "
        "    $ruta = $ruta.Split(' ')[0]; "
        "    $version = ''; "
        "    if (Test-Path $ruta) { try { $version = (Get-Item $ruta).VersionInfo.ProductVersion } catch { } } "
        "    if ($version) { Write-Output ($c.Producto + '|' + $version + '|Servicio ' + $servicio.Name + ' [' + $servicio.State + ']') } "
        "  } "
        "}"
    )
    _codigo, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=35)
    resultados: list[tuple[str, str, str]] = []
    detectados: set[tuple[str, str]] = set()
    for linea in salida.splitlines():
        partes = [parte.strip() for parte in linea.split("|", 2)]
        if len(partes) != 3 or not partes[1]:
            continue
        clave = (partes[0], partes[1])
        if clave in detectados:
            continue
        detectados.add(clave)
        resultados.append((partes[0], partes[1], partes[2]))
    return resultados



def analizar_versiones_instaladas_y_cves_locales(resultado: ResultadoEquipo) -> None:
    """Obtiene versiones instaladas localmente de servicios y busca CVEs asociadas en NVD/NIST."""
    # La forma de descubrir versiones cambia según el sistema.
    if os.name == "nt":
        versiones_locales = obtener_versiones_instaladas_servicios_windows()
    else:
        versiones_locales = obtener_versiones_instaladas_servicios_linux(resultado.puertos_abiertos)

    if not versiones_locales:
        return

    resultado.versiones_servicios.extend(
        [f"{producto} {version} | Evidencia local: {evidencia}" for producto, version, evidencia in versiones_locales]
    )

    # Para no alargar demasiado la consulta, se revisan solo algunos servicios detectados.
    vulnerabilidades: list[tuple[float, str]] = []
    vistas: set[str] = set()
    for producto, version, _evidencia in versiones_locales[:6]:
        for puntuacion, descripcion in consultar_cves_producto(producto, version):
            if descripcion in vistas:
                continue
            vistas.add(descripcion)
            vulnerabilidades.append((puntuacion, descripcion))

    vulnerabilidades.sort(key=lambda dato: dato[0], reverse=True)
    if vulnerabilidades:
        resultado.vulnerabilidades_cve.extend(
            [descripcion for _, descripcion in vulnerabilidades[:15] if descripcion not in resultado.vulnerabilidades_cve]
        )
        # Se añade un aviso general según la gravedad más alta encontrada.
        maxima = vulnerabilidades[0][0]
        if maxima >= 9.0:
            resultado.hallazgos_host.append("[ALTO] Se detectaron CVEs críticos asociados a versiones instaladas localmente")
        elif maxima >= 7.0:
            resultado.hallazgos_host.append("[ALTO] Se detectaron CVEs altos asociados a versiones instaladas localmente")
        elif maxima > 0:
            resultado.hallazgos_host.append("[MEDIO] Se detectaron CVEs asociados a versiones instaladas localmente")



def detectar_puertos_escucha_locales_windows() -> tuple[list[ResultadoPuerto], list[str]]:
    """Extrae puertos en escucha a partir de `netstat` en Windows."""
    if not shutil.which("netstat"):
        return [], ["No se encontró netstat para revisar puertos en escucha"]

    codigo, salida = ejecutar_comando_seguro(["netstat", "-ano"])
    if codigo is None or not salida:
        return [], ["No se pudo obtener la lista de puertos en escucha"]

    resultados: dict[int, ResultadoPuerto] = {}
    lineas_resumen: list[str] = []
    for linea in salida.splitlines():
        if "LISTENING" not in linea.upper() and "ESCUCHANDO" not in linea.upper():
            continue
        partes = linea.split()
        if len(partes) < 2:
            continue
        direccion_local = partes[1]
        puerto_texto = direccion_local.rsplit(":", 1)[-1].strip("[]")
        if not puerto_texto.isdigit():
            continue
        puerto = int(puerto_texto)
        servicio = PUERTOS_COMUNES.get(puerto, "Servicio en escucha")
        resultados[puerto] = ResultadoPuerto(numero=puerto, servicio=servicio, estado="Abierto")
        lineas_resumen.append(linea.strip())

    return sorted(resultados.values(), key=lambda dato: dato.numero), resumir_lineas("\n".join(lineas_resumen), 10)



def detectar_puertos_escucha_locales() -> tuple[list[ResultadoPuerto], list[str]]:
    """Selecciona el método adecuado según el sistema operativo para detectar puertos en escucha."""
    if platform.system().lower() == "windows":
        return detectar_puertos_escucha_locales_windows()
    return detectar_puertos_escucha_locales_linux()



def obtener_resumen_firewall_windows() -> tuple[list[str], list[str]]:
    """Recoge el estado del firewall en Windows usando netsh."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if not shutil.which("netsh"):
        return informacion, ["[MEDIO] No se encontró netsh para consultar el firewall"]

    _, salida = ejecutar_comando_seguro(["netsh", "advfirewall", "show", "allprofiles"])
    lineas = resumir_lineas(salida, 16)
    informacion.extend([f"Firewall Windows: {linea}" for linea in lineas])
    salida_mayus = salida.upper()
    if "STATE ON" in salida_mayus or "ESTADO ACTIVADO" in salida_mayus:
        hallazgos.append("[INFO] El firewall de Windows muestra perfiles activos")
    elif "STATE OFF" in salida_mayus or "ESTADO DESACTIVADO" in salida_mayus:
        hallazgos.append("[ALTO] Se detectó al menos un perfil del firewall desactivado")
    else:
        hallazgos.append("[MEDIO] No se pudo interpretar con claridad el estado del firewall")
    return informacion, hallazgos



def obtener_resumen_firewall() -> tuple[list[str], list[str]]:
    """Redirige la consulta del firewall a la implementación adecuada del sistema."""
    if platform.system().lower() == "windows":
        return obtener_resumen_firewall_windows()
    return obtener_resumen_firewall_linux()



def obtener_resumen_actualizaciones_windows() -> tuple[list[str], list[str]]:
    """Intenta obtener un resumen básico de parches instalados recientemente en Windows."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar actualizaciones"], [
            "[MEDIO] No se pudo consultar el estado de actualizaciones en Windows"
        ]

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn | Format-Table -HideTableHeaders",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=20)
    lineas = resumir_lineas(salida, 6)
    if any(linea for linea in lineas if linea.strip()):
        return ["Últimos parches instalados:"] + lineas, ["[INFO] Se recuperó un resumen de parches instalados"]
    return ["No se pudo obtener el historial de parches recientes"], ["[MEDIO] No fue posible revisar parches recientes"]



def obtener_resumen_actualizaciones() -> tuple[list[str], list[str]]:
    """Consulta información básica de actualizaciones pendientes o recientes."""
    if platform.system().lower() == "windows":
        return obtener_resumen_actualizaciones_windows()
    return obtener_resumen_actualizaciones_linux()



def obtener_politica_contrasenas_windows() -> tuple[list[str], list[str]]:
    """Obtiene un resumen básico de la política de contraseñas en Windows."""
    if not shutil.which("net"):
        return ["No se encontró el comando net para revisar la política de contraseñas"], [
            "[MEDIO] No se pudo consultar la política de contraseñas en Windows"
        ]

    _, salida = ejecutar_comando_seguro(["net", "accounts"], timeout=15)
    informacion = [f"Política Windows: {linea}" for linea in resumir_lineas(salida, 12)]
    hallazgos: list[str] = []
    salida_minuscula = salida.lower()

    coincidencia_longitud = re.search(r"minimum password length\s+([0-9]+)|longitud mínima.*?([0-9]+)", salida_minuscula)
    if coincidencia_longitud:
        valor = next((grupo for grupo in coincidencia_longitud.groups() if grupo), None)
        if valor and int(valor) < 12:
            hallazgos.append("[MEDIO] La longitud mínima de contraseña es inferior a 12 caracteres")

    if "lockout threshold" in salida_minuscula and "never" in salida_minuscula:
        hallazgos.append("[MEDIO] El bloqueo por intentos fallidos parece no estar habilitado")

    return informacion, hallazgos



def obtener_politica_contrasenas() -> tuple[list[str], list[str]]:
    """Selecciona la consulta de política de contraseñas adecuada al sistema."""
    if os.name == "nt":
        return obtener_politica_contrasenas_windows()
    return obtener_politica_contrasenas_linux()



def obtener_resumen_antivirus_windows() -> tuple[list[str], list[str]]:
    """Consulta el estado básico de Microsoft Defender cuando está disponible."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar antivirus"], []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled | Format-List",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=20)
    lineas = resumir_lineas(salida, 8)
    hallazgos: list[str] = []
    salida_mayus = salida.upper()
    if "FALSE" in salida_mayus:
        hallazgos.append("[ALTO] Alguna protección de Microsoft Defender aparece desactivada")
    elif "TRUE" in salida_mayus:
        hallazgos.append("[INFO] Microsoft Defender reporta protecciones activas")
    return [f"Defender: {linea}" for linea in lineas], hallazgos



def obtener_resumen_antivirus() -> tuple[list[str], list[str]]:
    """Obtiene una visión básica de la protección antimalware o de auditoría local."""
    if platform.system().lower() == "windows":
        return obtener_resumen_antivirus_windows()
    return obtener_resumen_antivirus_linux()



def obtener_resumen_ssh_y_acceso_remoto_windows() -> tuple[list[str], list[str]]:
    """Revisa RDP y OpenSSH Server en Windows cuando se dispone de herramientas del sistema."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if shutil.which("powershell"):
        comando_rdp = [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
        ]
        _, salida_rdp = ejecutar_comando_seguro(comando_rdp)
        if salida_rdp.strip() == "0":
            informacion.append("RDP: habilitado")
            hallazgos.append("[MEDIO] El acceso remoto por RDP está habilitado")
        elif salida_rdp.strip() == "1":
            informacion.append("RDP: deshabilitado")

        comando_sshd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
        ]
        _, salida_sshd = ejecutar_comando_seguro(comando_sshd)
        if salida_sshd.strip():
            informacion.append(f"OpenSSH Server: {salida_sshd.strip()}")
            if "running" in salida_sshd.lower():
                hallazgos.append("[MEDIO] El servicio OpenSSH Server está activo")

    if not informacion:
        informacion.append("No se pudo obtener información de acceso remoto en Windows")

    return informacion, hallazgos



def obtener_resumen_ssh_y_acceso_remoto() -> tuple[list[str], list[str]]:
    """Selecciona la comprobación de acceso remoto según el sistema operativo."""
    if os.name == "nt":
        return obtener_resumen_ssh_y_acceso_remoto_windows()
    return obtener_resumen_ssh_y_acceso_remoto_linux()



def obtener_resumen_usuarios_y_privilegios() -> tuple[list[str], list[str]]:
    """Recoge información del usuario actual y detecta indicios de privilegios elevados."""
    informacion: list[str] = []
    hallazgos: list[str] = []
    usuario_actual = getpass.getuser()
    informacion.append(f"Usuario actual: {usuario_actual}")

    if os.name == "nt":
        _, salida = ejecutar_comando_seguro(["whoami", "/groups"])
        lineas = resumir_lineas(salida, 10)
        informacion.extend([f"Grupo Windows: {linea}" for linea in lineas])
        if "S-1-5-32-544" in salida or "Administrators" in salida:
            hallazgos.append("[MEDIO] El usuario actual pertenece al grupo de administradores")
        return informacion, hallazgos

    grupos = []
    try:
        import grp
        grupos = sorted({grp.getgrgid(grupo_id).gr_name for grupo_id in os.getgroups()})
    except Exception:
        grupos = []

    if grupos:
        informacion.append(f"Grupos del usuario: {', '.join(grupos)}")
        if {"sudo", "wheel"} & set(grupos):
            hallazgos.append("[MEDIO] El usuario actual tiene pertenencia a grupos administrativos")

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        hallazgos.append("[ALTO] La auditoría local se está ejecutando como root")

    return informacion, hallazgos



def comprobar_permisos_sensibles_windows() -> tuple[list[str], list[str]]:
    """Consulta de forma básica la ACL del perfil del usuario en Windows."""
    informacion: list[str] = []
    hallazgos: list[str] = []
    ruta_ssh = Path.home() / ".ssh"
    if ruta_ssh.exists() and shutil.which("icacls"):
        _, salida = ejecutar_comando_seguro(["icacls", str(ruta_ssh)])
        lineas = resumir_lineas(salida, 8)
        informacion.extend([f"ACL {ruta_ssh}: {linea}" for linea in lineas])
    else:
        informacion.append("No se pudo revisar la ACL de .ssh o la carpeta no existe")
    return informacion, hallazgos



def comprobar_permisos_sensibles() -> tuple[list[str], list[str]]:
    """Selecciona la comprobación de permisos adecuada para el sistema operativo."""
    if os.name == "nt":
        return comprobar_permisos_sensibles_windows()
    return comprobar_permisos_sensibles_linux()



def obtener_resumen_tareas_programadas_windows() -> tuple[list[str], list[str]]:
    """Obtiene un resumen de tareas programadas en Windows."""
    if not shutil.which("schtasks"):
        return ["No se encontró schtasks para revisar tareas programadas"], []

    _, salida = ejecutar_comando_seguro(["schtasks", "/query", "/fo", "LIST", "/v"], timeout=20)
    lineas = resumir_lineas(salida, 12)
    return ["Tareas programadas (muestra):"] + lineas, []



def obtener_resumen_tareas_programadas() -> tuple[list[str], list[str]]:
    """Selecciona la comprobación de tareas programadas según el sistema operativo."""
    if os.name == "nt":
        return obtener_resumen_tareas_programadas_windows()
    return obtener_resumen_tareas_programadas_linux()



def obtener_resumen_comparticiones_windows() -> tuple[list[str], list[str]]:
    """Obtiene el listado de comparticiones en Windows usando net share."""
    if not shutil.which("net"):
        return ["No se encontró el comando net para consultar comparticiones"], []

    _, salida = ejecutar_comando_seguro(["net", "share"], timeout=15)
    lineas = [linea.strip() for linea in salida.splitlines() if linea.strip()]
    informacion = ["Comparticiones Windows (muestra):"] + resumir_lineas("\n".join(lineas), 10)
    hallazgos: list[str] = []
    if any(linea.startswith(("ADMIN$", "C$", "IPC$")) for linea in lineas):
        hallazgos.append("[INFO] Se detectaron comparticiones administrativas por defecto en Windows")
    return informacion, hallazgos



def obtener_resumen_comparticiones() -> tuple[list[str], list[str]]:
    """Selecciona la consulta de comparticiones según el sistema operativo."""
    if os.name == "nt":
        return obtener_resumen_comparticiones_windows()
    return obtener_resumen_comparticiones_linux()



def obtener_endurecimiento_sistema() -> tuple[list[str], list[str]]:
    """Selecciona la comprobación de endurecimiento adicional según el sistema operativo."""
    if os.name == "nt":
        return obtener_endurecimiento_windows()
    return obtener_endurecimiento_linux()



def obtener_resumen_servicios() -> tuple[list[str], list[str]]:
    """Obtiene un listado resumido de servicios habilitados o en ejecución."""
    if os.name == "nt":
        if not shutil.which("powershell"):
            return ["PowerShell no está disponible para consultar servicios"], []
        comando = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 10 Name,DisplayName | Format-Table -HideTableHeaders",
        ]
        _, salida = ejecutar_comando_seguro(comando, timeout=20)
        return ["Servicios en ejecución (muestra):"] + resumir_lineas(salida, 10), []

    return obtener_resumen_servicios_linux()


def notificar_progreso_local(
    notificar_progreso: NotificadorProgreso | None,
    paso_actual: int,
    total_pasos: int,
    mensaje: str,
    resultado_equipo: ResultadoEquipo | None = None,
) -> None:
    """Publica el avance de la auditoría local para alimentar la barra de progreso."""
    if notificar_progreso is None:
        return

    porcentaje = (paso_actual / total_pasos) * 95 if total_pasos else 95.0
    notificar_progreso(
        ProgresoAuditoria(
            completados=paso_actual,
            total=total_pasos,
            porcentaje=porcentaje,
            mensaje=mensaje,
            resultado_equipo=resultado_equipo,
        )
    )



def construir_resultado_local(
    parametros: ParametrosAuditoria,
    notificar_progreso: NotificadorProgreso | None = None,
) -> ResultadoEquipo:
    """Compone el resultado completo de la auditoría local del equipo actual."""
    # Se recoge primero la identidad básica del equipo para usarla en todo el informe.
    ip_principal = obtener_ip_principal_local()
    nombre_host = socket.gethostname()
    fqdn = socket.getfqdn()
    sistema = f"{platform.system()} {platform.release()} ({platform.machine()})"
    total_pasos = 13 if os.name == "nt" else 12

    resultado = ResultadoEquipo(
        ip=ip_principal,
        activo=True,
        tiempo_respuesta_ms="Local",
        categoria_latencia="Local",
        ttl="No aplica",
        sistema_operativo_probable=sistema,
        nombre_host=nombre_host,
    )

    resultado.informacion_sistema.extend(
        [
            f"Modo de auditoría: local del equipo",
            f"Hostname: {nombre_host}",
            f"FQDN: {fqdn}",
            f"Sistema operativo detectado: {sistema}",
            f"Direcciones IP detectadas: {', '.join(obtener_ips_locales())}",
        ]
    )

    notificar_progreso_local(notificar_progreso, 1, total_pasos, "1/1 - preparando información base del equipo")

    # A partir de aquí se van añadiendo bloques de información uno por uno.
    puertos_locales, resumen_puertos = detectar_puertos_escucha_locales()
    resultado.puertos_abiertos = puertos_locales
    if resumen_puertos:
        resultado.comprobaciones_adicionales.append("Puertos en escucha locales:")
        resultado.comprobaciones_adicionales.extend(resumen_puertos)
    if len(puertos_locales) > 25:
        resultado.hallazgos_host.append(f"[MEDIO] Se detectaron {len(puertos_locales)} puertos locales en escucha")
    notificar_progreso_local(notificar_progreso, 2, total_pasos, "1/1 - revisando puertos locales en escucha")

    informacion_firewall, hallazgos_firewall = obtener_resumen_firewall()
    resultado.informacion_sistema.extend(informacion_firewall)
    resultado.hallazgos_host.extend(hallazgos_firewall)
    notificar_progreso_local(notificar_progreso, 3, total_pasos, "1/1 - comprobando firewall y exposición local")

    informacion_actualizaciones, hallazgos_actualizaciones = obtener_resumen_actualizaciones()
    resultado.informacion_sistema.extend(informacion_actualizaciones)
    resultado.hallazgos_host.extend(hallazgos_actualizaciones)
    notificar_progreso_local(notificar_progreso, 4, total_pasos, "1/1 - revisando actualizaciones del sistema")

    informacion_politica, hallazgos_politica = obtener_politica_contrasenas()
    resultado.informacion_sistema.extend(informacion_politica)
    resultado.hallazgos_host.extend(hallazgos_politica)
    notificar_progreso_local(notificar_progreso, 5, total_pasos, "1/1 - analizando políticas y contraseñas")

    informacion_antivirus, hallazgos_antivirus = obtener_resumen_antivirus()
    resultado.informacion_sistema.extend(informacion_antivirus)
    resultado.hallazgos_host.extend(hallazgos_antivirus)
    notificar_progreso_local(notificar_progreso, 6, total_pasos, "1/1 - comprobando antivirus y protecciones activas")

    informacion_acceso_remoto, hallazgos_acceso_remoto = obtener_resumen_ssh_y_acceso_remoto()
    resultado.informacion_sistema.extend(informacion_acceso_remoto)
    resultado.hallazgos_host.extend(hallazgos_acceso_remoto)
    notificar_progreso_local(notificar_progreso, 7, total_pasos, "1/1 - revisando acceso remoto y superficie expuesta")

    informacion_usuarios, hallazgos_usuarios = obtener_resumen_usuarios_y_privilegios()
    resultado.informacion_sistema.extend(informacion_usuarios)
    resultado.hallazgos_host.extend(hallazgos_usuarios)
    notificar_progreso_local(notificar_progreso, 8, total_pasos, "1/1 - recopilando usuarios y privilegios locales")

    informacion_permisos, hallazgos_permisos = comprobar_permisos_sensibles()
    resultado.informacion_sistema.extend(informacion_permisos)
    resultado.hallazgos_host.extend(hallazgos_permisos)
    notificar_progreso_local(notificar_progreso, 9, total_pasos, "1/1 - comprobando permisos sensibles del sistema")

    informacion_servicios, hallazgos_servicios = obtener_resumen_servicios()
    resultado.informacion_sistema.extend(informacion_servicios)
    resultado.hallazgos_host.extend(hallazgos_servicios)
    notificar_progreso_local(notificar_progreso, 10, total_pasos, "1/1 - inventariando servicios y tareas del sistema")

    informacion_tareas, hallazgos_tareas = obtener_resumen_tareas_programadas()
    resultado.informacion_sistema.extend(informacion_tareas)
    resultado.hallazgos_host.extend(hallazgos_tareas)

    informacion_comparticiones, hallazgos_comparticiones = obtener_resumen_comparticiones()
    resultado.informacion_sistema.extend(informacion_comparticiones)
    resultado.hallazgos_host.extend(hallazgos_comparticiones)

    informacion_endurecimiento, hallazgos_endurecimiento = obtener_endurecimiento_sistema()
    resultado.informacion_sistema.extend(informacion_endurecimiento)
    resultado.hallazgos_host.extend(hallazgos_endurecimiento)
    notificar_progreso_local(notificar_progreso, 11, total_pasos, "1/1 - evaluando endurecimiento y comparticiones")

    # Al final se intenta relacionar lo instalado con posibles fallos conocidos.
    analizar_versiones_instaladas_y_cves_locales(resultado)
    notificar_progreso_local(notificar_progreso, 12, total_pasos, "1/1 - correlacionando versiones instaladas y CVEs")

    # Este bloque extra solo existe en Windows porque usa herramientas propias de ese sistema.
    if os.name == "nt":
        informacion_windows, hallazgos_windows = obtener_controles_windows_avanzados()
        resultado.informacion_sistema.extend(informacion_windows)
        resultado.hallazgos_host.extend(hallazgos_windows)
        notificar_progreso_local(notificar_progreso, total_pasos, total_pasos, "1/1 - ejecutando comprobaciones avanzadas de Windows")

    # Si no salió nada importante, también se deja indicado para que el informe no quede vacío.
    if not resultado.hallazgos_host:
        resultado.hallazgos_host.append("[INFO] No se detectaron hallazgos de riesgo destacados en la comprobación local básica")

    return resultado



def auditar_equipo_local(
    parametros: ParametrosAuditoria,
    notificar_progreso: NotificadorProgreso | None = None,
) -> ResumenAuditoria:
    """Ejecuta una auditoría local avanzada del equipo actual y empaqueta el resultado."""
    resultado = construir_resultado_local(parametros, notificar_progreso=notificar_progreso)
    return ResumenAuditoria(parametros=parametros, resultados=[resultado])
