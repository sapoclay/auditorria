"""Comprobaciones específicas de Linux para la auditoría local."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from .auditoria_local_utils import (
    ejecutar_comando_seguro,
    leer_archivo_texto,
    obtener_estado_servicio_linux,
    obtener_valor_configuracion,
    obtener_version_desde_comandos,
    obtener_version_paquete_linux,
    resumir_lineas,
)
from .configuracion import PUERTOS_COMUNES
from .modelos import ResultadoPuerto


def obtener_versiones_instaladas_servicios_linux(puertos_abiertos: list[ResultadoPuerto]) -> list[tuple[str, str, str]]:
    """Detecta versiones realmente instaladas de servicios comunes en Linux usando paquetes y comandos locales."""
    puertos = {puerto.numero for puerto in puertos_abiertos}
    candidatos = [
        {
            "producto": "Apache HTTP Server",
            "puertos": {80, 443, 8080, 8443},
            "paquetes": ["apache2", "httpd"],
            "servicios": ["apache2", "httpd"],
            "comandos": [["apache2", "-v"], ["httpd", "-v"], ["apachectl", "-v"]],
        },
        {
            "producto": "nginx",
            "puertos": {80, 443, 8080, 8443},
            "paquetes": ["nginx"],
            "servicios": ["nginx"],
            "comandos": [["nginx", "-v"]],
        },
        {
            "producto": "OpenSSH",
            "puertos": {22},
            "paquetes": ["openssh-server", "openssh"],
            "servicios": ["ssh", "sshd"],
            "comandos": [["sshd", "-V"], ["ssh", "-V"]],
        },
        {
            "producto": "Redis",
            "puertos": {6379},
            "paquetes": ["redis-server", "redis"],
            "servicios": ["redis-server", "redis"],
            "comandos": [["redis-server", "--version"], ["redis-cli", "--version"]],
        },
        {
            "producto": "MySQL",
            "puertos": {3306},
            "paquetes": ["mysql-server", "mysql-community-server", "mariadb-server"],
            "servicios": ["mysql", "mysqld", "mariadb"],
            "comandos": [["mysqld", "--version"], ["mysql", "--version"], ["mariadbd", "--version"]],
        },
        {
            "producto": "PostgreSQL",
            "puertos": {5432},
            "paquetes": ["postgresql"],
            "servicios": ["postgresql"],
            "comandos": [["postgres", "--version"], ["psql", "--version"]],
        },
        {
            "producto": "Samba",
            "puertos": {139, 445},
            "paquetes": ["samba"],
            "servicios": ["smbd", "nmbd", "samba"],
            "comandos": [["smbd", "--version"]],
        },
        {
            "producto": "Bind",
            "puertos": {53},
            "paquetes": ["bind9"],
            "servicios": ["bind9", "named"],
            "comandos": [["named", "-v"]],
        },
        {
            "producto": "Postfix",
            "puertos": {25, 587},
            "paquetes": ["postfix"],
            "servicios": ["postfix"],
            "comandos": [["postconf", "mail_version"]],
        },
        {
            "producto": "CUPS",
            "puertos": {631},
            "paquetes": ["cups"],
            "servicios": ["cups", "cupsd"],
            "comandos": [["cups-config", "--version"], ["lpstat", "-r"]],
        },
    ]

    resultados: list[tuple[str, str, str]] = []
    detectados: set[tuple[str, str]] = set()
    for candidato in candidatos:
        if not (puertos & candidato["puertos"] or obtener_estado_servicio_linux(candidato["servicios"])):
            continue

        version, evidencia = obtener_version_paquete_linux(candidato["paquetes"])
        if version is None:
            version, evidencia = obtener_version_desde_comandos(candidato["comandos"])
        if version is None:
            continue

        clave = (str(candidato["producto"]), version)
        if clave in detectados:
            continue
        detectados.add(clave)
        evidencia_final = evidencia or obtener_estado_servicio_linux(candidato["servicios"]) or "Versión local detectada"
        resultados.append((str(candidato["producto"]), version, evidencia_final))

    return resultados


def detectar_puertos_escucha_locales_linux() -> tuple[list[ResultadoPuerto], list[str]]:
    """Extrae puertos en escucha desde `ss` o `netstat` en Linux."""
    comandos = []
    if shutil.which("ss"):
        comandos.append(["ss", "-tulpn"])
    if shutil.which("netstat"):
        comandos.append(["netstat", "-tulpn"])

    for comando in comandos:
        codigo, salida = ejecutar_comando_seguro(comando)
        if codigo is None or not salida:
            continue

        resultados: dict[int, ResultadoPuerto] = {}
        lineas_resumen: list[str] = []
        for linea in salida.splitlines():
            if ":" not in linea or "LISTEN" not in linea.upper():
                continue
            partes = linea.split()
            try:
                direccion_local = partes[4]
            except IndexError:
                continue
            puerto_texto = direccion_local.rsplit(":", 1)[-1].strip("[]")
            if not puerto_texto.isdigit():
                continue
            puerto = int(puerto_texto)
            servicio = PUERTOS_COMUNES.get(puerto, "Servicio en escucha")
            resultados[puerto] = ResultadoPuerto(numero=puerto, servicio=servicio, estado="Abierto")
            lineas_resumen.append(linea.strip())

        return sorted(resultados.values(), key=lambda dato: dato.numero), resumir_lineas("\n".join(lineas_resumen), 10)

    return [], ["No se pudo obtener la lista de puertos en escucha con ss/netstat"]


def obtener_resumen_firewall_linux() -> tuple[list[str], list[str]]:
    """Recoge el estado del firewall en Linux usando las herramientas disponibles."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if shutil.which("ufw"):
        _, salida = ejecutar_comando_seguro(["ufw", "status", "verbose"])
        lineas = resumir_lineas(salida, 12)
        informacion.extend([f"UFW: {linea}" for linea in lineas])
        salida_mayus = salida.upper()
        if "STATUS: INACTIVE" in salida_mayus:
            hallazgos.append("[ALTO] UFW aparece inactivo en el equipo local")
        elif "STATUS: ACTIVE" in salida_mayus:
            hallazgos.append("[INFO] UFW aparece activo")
        return informacion, hallazgos

    if shutil.which("firewall-cmd"):
        _, estado = ejecutar_comando_seguro(["firewall-cmd", "--state"])
        informacion.append(f"firewalld: {estado or 'Sin datos'}")
        if "running" in estado.lower():
            hallazgos.append("[INFO] firewalld aparece activo")
        else:
            hallazgos.append("[MEDIO] No se pudo confirmar firewalld en ejecución")
        return informacion, hallazgos

    hallazgos.append("[MEDIO] No se detectó una herramienta conocida para consultar el firewall")
    return informacion, hallazgos


def obtener_resumen_actualizaciones_linux() -> tuple[list[str], list[str]]:
    """Busca actualizaciones pendientes con el gestor de paquetes disponible en Linux."""
    candidatos = [
        (["apt", "list", "--upgradable"], "APT"),
        (["dnf", "check-update"], "DNF"),
        (["yum", "check-update"], "YUM"),
        (["zypper", "list-updates"], "ZYPPER"),
    ]

    for comando, nombre in candidatos:
        if not shutil.which(comando[0]):
            continue
        codigo, salida = ejecutar_comando_seguro(comando, timeout=20)
        if codigo is None:
            continue
        lineas = [linea for linea in salida.splitlines() if linea.strip()]
        if nombre == "APT":
            paquetes = [linea for linea in lineas if "/" in linea and "upgradable" in linea.lower()]
        else:
            paquetes = [linea for linea in lineas if not linea.lower().startswith(("last metadata", "cargando", "loading"))]
        if paquetes:
            return [f"Actualizaciones pendientes detectadas con {nombre}: {len(paquetes)}"] + resumir_lineas("\n".join(paquetes), 6), [
                f"[MEDIO] Se detectaron {len(paquetes)} actualizaciones pendientes"
            ]
        return [f"No se detectaron actualizaciones pendientes con {nombre}"], ["[INFO] No se observaron actualizaciones pendientes en la comprobación básica"]

    return ["No se encontró un gestor de paquetes compatible para comprobar actualizaciones"], [
        "[MEDIO] No se pudo comprobar si existen actualizaciones pendientes"
    ]


def obtener_politica_contrasenas_linux() -> tuple[list[str], list[str]]:
    """Obtiene parámetros básicos de la política de contraseñas en Linux."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    login_defs = leer_archivo_texto(Path("/etc/login.defs"))
    if login_defs:
        for clave in ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "UMASK"]:
            valor = obtener_valor_configuracion(login_defs, clave)
            if valor is not None:
                informacion.append(f"Política {clave}: {valor}")
                if clave == "PASS_MAX_DAYS" and valor.isdigit() and int(valor) > 365:
                    hallazgos.append("[MEDIO] La caducidad máxima de contraseñas es superior a 365 días")
                if clave == "UMASK" and valor in {"022", "002", "000"}:
                    hallazgos.append("[MEDIO] La política UMASK por defecto es relativamente permisiva")

    pwquality = leer_archivo_texto(Path("/etc/security/pwquality.conf"))
    if pwquality:
        minlen = obtener_valor_configuracion(pwquality, "minlen")
        if minlen is not None:
            informacion.append(f"Política minlen: {minlen}")
            if minlen.isdigit() and int(minlen) < 12:
                hallazgos.append("[MEDIO] La longitud mínima de contraseña configurada es inferior a 12 caracteres")

    if not informacion:
        informacion.append("No se pudo leer una política local de contraseñas suficientemente clara")

    return informacion, hallazgos


def obtener_resumen_antivirus_linux() -> tuple[list[str], list[str]]:
    """Busca procesos o servicios habituales de seguridad en Linux de manera orientativa."""
    servicios_detectados = []
    for servicio in ["clamav-daemon", "clamd", "falcon-sensor", "auditd"]:
        if shutil.which("systemctl"):
            _, salida = ejecutar_comando_seguro(["systemctl", "is-active", servicio])
            if "active" in salida.lower():
                servicios_detectados.append(servicio)

    if servicios_detectados:
        return [f"Servicios de seguridad detectados: {', '.join(servicios_detectados)}"], [
            "[INFO] Se detectaron servicios de seguridad activos"
        ]
    return ["No se detectaron servicios de seguridad habituales mediante systemctl"], [
        "[MEDIO] No se detectaron servicios de seguridad habituales"
    ]


def obtener_resumen_ssh_y_acceso_remoto_linux() -> tuple[list[str], list[str]]:
    """Revisa parámetros básicos de SSH y acceso remoto en Linux."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if shutil.which("systemctl"):
        _, estado_sshd = ejecutar_comando_seguro(["systemctl", "is-active", "sshd"])
        _, estado_ssh = ejecutar_comando_seguro(["systemctl", "is-active", "ssh"])
        estado = estado_sshd if estado_sshd and estado_sshd != "unknown" else estado_ssh
        if estado:
            informacion.append(f"Servicio SSH: {estado}")

    texto_sshd = leer_archivo_texto(Path("/etc/ssh/sshd_config"))
    if texto_sshd:
        for clave in ["PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication"]:
            valor = obtener_valor_configuracion(texto_sshd, clave)
            if valor is not None:
                informacion.append(f"SSH {clave}: {valor}")
                if clave == "PermitRootLogin" and valor.lower() in {"yes", "without-password", "prohibit-password no"}:
                    hallazgos.append("[ALTO] SSH permite inicio de sesión directo de root o una variante permisiva")
                if clave == "PasswordAuthentication" and valor.lower() == "yes":
                    hallazgos.append("[MEDIO] SSH permite autenticación por contraseña")
                if clave == "PubkeyAuthentication" and valor.lower() == "no":
                    hallazgos.append("[MEDIO] SSH no tiene habilitada la autenticación por clave pública")
    else:
        informacion.append("No se encontró /etc/ssh/sshd_config")

    return informacion, hallazgos


def comprobar_permisos_sensibles_linux() -> tuple[list[str], list[str]]:
    """Revisa algunos permisos sensibles del sistema y del directorio personal en Linux."""
    informacion: list[str] = []
    hallazgos: list[str] = []
    rutas = [Path("/etc/passwd"), Path("/etc/shadow"), Path.home() / ".ssh"]

    for ruta in rutas:
        if not ruta.exists():
            continue
        modo = stat.S_IMODE(ruta.stat().st_mode)
        informacion.append(f"Permisos {ruta}: {oct(modo)}")
        if ruta.name == "shadow" and modo & 0o077:
            hallazgos.append("[ALTO] /etc/shadow parece accesible por grupo u otros")
        if ruta.name == ".ssh" and modo & 0o077:
            hallazgos.append("[MEDIO] El directorio .ssh del usuario tiene permisos más abiertos de lo deseado")

    umask_actual = os.umask(0)
    os.umask(umask_actual)
    informacion.append(f"Umask actual del proceso: {oct(umask_actual)}")
    if umask_actual in {0o000, 0o002}:
        hallazgos.append("[MEDIO] La umask del proceso permite permisos relativamente abiertos")

    return informacion, hallazgos


def obtener_resumen_tareas_programadas_linux() -> tuple[list[str], list[str]]:
    """Obtiene un resumen básico de cron y temporizadores programados en Linux."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if shutil.which("crontab"):
        _, salida = ejecutar_comando_seguro(["crontab", "-l"], timeout=10)
        lineas = [linea for linea in salida.splitlines() if linea.strip() and not linea.strip().startswith("#")]
        if lineas:
            informacion.append(f"Crontab del usuario: {len(lineas)} tareas activas")
            informacion.extend(resumir_lineas("\n".join(lineas), 6))

    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        tareas_cron_d = [ruta.name for ruta in cron_d.iterdir() if ruta.is_file()]
        if tareas_cron_d:
            informacion.append(f"Archivos en /etc/cron.d: {', '.join(sorted(tareas_cron_d)[:8])}")

    if shutil.which("systemctl"):
        _, salida = ejecutar_comando_seguro(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"], timeout=15)
        lineas = resumir_lineas(salida, 6)
        if lineas:
            informacion.append("Temporizadores systemd (muestra):")
            informacion.extend(lineas)

    if not informacion:
        informacion.append("No se obtuvo información significativa de tareas programadas")

    return informacion, hallazgos


def obtener_resumen_comparticiones_linux() -> tuple[list[str], list[str]]:
    """Revisa configuraciones sencillas de comparticiones Samba y NFS en Linux."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    smb_conf = leer_archivo_texto(Path("/etc/samba/smb.conf"))
    if smb_conf:
        informacion.append("Samba: se encontró /etc/samba/smb.conf")
        if "guest ok = yes" in smb_conf.lower() or "public = yes" in smb_conf.lower():
            hallazgos.append("[ALTO] Samba parece permitir acceso de invitado en alguna compartición")

    exports = leer_archivo_texto(Path("/etc/exports"))
    if exports:
        lineas = [linea for linea in exports.splitlines() if linea.strip() and not linea.strip().startswith("#")]
        if lineas:
            informacion.append("NFS exports configurados:")
            informacion.extend(resumir_lineas("\n".join(lineas), 6))
            hallazgos.append("[MEDIO] Existen comparticiones NFS configuradas; conviene revisar su alcance")

    if not informacion:
        informacion.append("No se detectaron comparticiones Samba/NFS configuradas de forma evidente")

    return informacion, hallazgos


def obtener_endurecimiento_linux() -> tuple[list[str], list[str]]:
    """Consulta algunos controles de endurecimiento del kernel y del sistema en Linux."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    aslr = leer_archivo_texto(Path("/proc/sys/kernel/randomize_va_space")).strip()
    if aslr:
        informacion.append(f"ASLR (randomize_va_space): {aslr}")
        if aslr == "0":
            hallazgos.append("[ALTO] ASLR está desactivado")
        elif aslr == "1":
            hallazgos.append("[MEDIO] ASLR está en modo parcial")

    suid_dumpable = leer_archivo_texto(Path("/proc/sys/fs/suid_dumpable")).strip()
    if suid_dumpable:
        informacion.append(f"SUID dumpable: {suid_dumpable}")
        if suid_dumpable != "0":
            hallazgos.append("[MEDIO] El sistema permite volcados para binarios con privilegios")

    if shutil.which("systemctl"):
        _, salida = ejecutar_comando_seguro(["systemctl", "is-enabled", "apparmor"], timeout=10)
        if salida.strip():
            informacion.append(f"AppArmor: {salida.strip()}")
        _, salida_selinux = ejecutar_comando_seguro(["getenforce"], timeout=10)
        if salida_selinux.strip():
            informacion.append(f"SELinux: {salida_selinux.strip()}")
            if salida_selinux.strip().lower() == "disabled":
                hallazgos.append("[MEDIO] SELinux aparece deshabilitado")

    if not informacion:
        informacion.append("No se pudieron consultar controles adicionales de endurecimiento")

    return informacion, hallazgos


def obtener_resumen_servicios_linux() -> tuple[list[str], list[str]]:
    """Obtiene un listado resumido de servicios habilitados en Linux."""
    if shutil.which("systemctl"):
        _, salida = ejecutar_comando_seguro(
            ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager", "--no-legend"],
            timeout=20,
        )
        return ["Servicios habilitados (muestra):"] + resumir_lineas(salida, 10), []

    return ["No se pudo obtener un resumen de servicios"], []
