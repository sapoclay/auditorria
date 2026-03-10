"""Comprobaciones avanzadas específicas de Windows para la auditoría local."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .auditoria_local_utils import ejecutar_comando_seguro, resumir_lineas


def obtener_endurecimiento_windows() -> tuple[list[str], list[str]]:
    """Consulta algunos controles de endurecimiento de Windows como UAC y SMBv1."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para comprobar endurecimiento adicional"], []

    comando_uac = [
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
    ]
    _, salida_uac = ejecutar_comando_seguro(comando_uac, timeout=10)
    if salida_uac.strip() == "1":
        informacion.append("UAC: habilitado")
    elif salida_uac.strip() == "0":
        informacion.append("UAC: deshabilitado")
        hallazgos.append("[ALTO] UAC aparece deshabilitado")

    comando_smb1 = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State",
    ]
    _, salida_smb1 = ejecutar_comando_seguro(comando_smb1, timeout=20)
    if salida_smb1.strip():
        informacion.append(f"SMB1: {salida_smb1.strip()}")
        if "enabled" in salida_smb1.lower():
            hallazgos.append("[ALTO] SMBv1 aparece habilitado")

    if not informacion:
        informacion.append("No se pudieron consultar controles adicionales de endurecimiento en Windows")

    return informacion, hallazgos


def obtener_bitlocker_windows() -> tuple[list[str], list[str]]:
    """Obtiene un resumen del estado de BitLocker en las unidades del sistema."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar BitLocker"], []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod | Format-Table -HideTableHeaders",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=25)
    lineas = resumir_lineas(salida, 10)
    hallazgos: list[str] = []
    salida_minuscula = salida.lower()
    if "off" in salida_minuscula or "protection off" in salida_minuscula:
        hallazgos.append("[MEDIO] Alguna unidad parece no tener BitLocker activo o protegido")
    elif salida.strip():
        hallazgos.append("[INFO] Se obtuvo un resumen de BitLocker")
    return ["BitLocker (muestra):"] + lineas, hallazgos


def obtener_cuentas_locales_windows() -> tuple[list[str], list[str]]:
    """Consulta cuentas locales relevantes y detecta situaciones comunes de riesgo."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar cuentas locales"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_usuarios = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,LastLogon | Format-Table -HideTableHeaders",
    ]
    _, salida_usuarios = ejecutar_comando_seguro(comando_usuarios, timeout=20)
    informacion.extend(["Usuarios locales (muestra):"] + resumir_lineas(salida_usuarios, 10))
    salida_minuscula = salida_usuarios.lower()
    if re.search(r"\bguest\b.*\btrue\b", salida_minuscula):
        hallazgos.append("[ALTO] La cuenta Guest aparece habilitada")
    if re.search(r"\badministrator\b.*\btrue\b", salida_minuscula):
        hallazgos.append("[MEDIO] La cuenta Administrator aparece habilitada")
    if "false" in salida_minuscula and "passwordrequired" in salida_minuscula.replace(" ", ""):
        hallazgos.append("[MEDIO] Existe al menos una cuenta local sin requerimiento de contraseña")

    comando_admins = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass | Format-Table -HideTableHeaders",
    ]
    _, salida_admins = ejecutar_comando_seguro(comando_admins, timeout=20)
    informacion.extend(["Miembros de Administrators (muestra):"] + resumir_lineas(salida_admins, 10))

    return informacion, hallazgos


def obtener_controles_remotos_windows() -> tuple[list[str], list[str]]:
    """Revisa RDP con NLA, WinRM y estado de servicios remotos habituales."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar controles remotos de Windows"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_nla = [
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication",
    ]
    _, salida_nla = ejecutar_comando_seguro(comando_nla, timeout=10)
    if salida_nla.strip() == "1":
        informacion.append("RDP NLA: habilitado")
    elif salida_nla.strip() == "0":
        informacion.append("RDP NLA: deshabilitado")
        hallazgos.append("[ALTO] RDP está habilitado sin Network Level Authentication")

    comando_winrm = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-Service WinRM | Select-Object -ExpandProperty Status",
    ]
    _, salida_winrm = ejecutar_comando_seguro(comando_winrm, timeout=10)
    if salida_winrm.strip():
        informacion.append(f"WinRM: {salida_winrm.strip()}")
        if "running" in salida_winrm.lower():
            hallazgos.append("[MEDIO] WinRM está activo; revise necesidad y restricciones")

    return informacion, hallazgos


def obtener_windows_update_y_reinicio() -> tuple[list[str], list[str]]:
    """Consulta Windows Update, servicio asociado e indicios de reinicio pendiente."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar Windows Update"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_wuauserv = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-Service wuauserv | Select-Object -ExpandProperty Status",
    ]
    _, salida_wuauserv = ejecutar_comando_seguro(comando_wuauserv, timeout=10)
    if salida_wuauserv.strip():
        informacion.append(f"Servicio Windows Update: {salida_wuauserv.strip()}")
        if "stopped" in salida_wuauserv.lower():
            hallazgos.append("[MEDIO] El servicio Windows Update está detenido")

    comando_reinicio = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'",
    ]
    _, salida_reinicio = ejecutar_comando_seguro(comando_reinicio, timeout=10)
    if salida_reinicio.strip().lower() == "true":
        informacion.append("Reinicio pendiente: sí")
        hallazgos.append("[MEDIO] El sistema tiene un reinicio pendiente tras actualizaciones")
    elif salida_reinicio.strip().lower() == "false":
        informacion.append("Reinicio pendiente: no")

    return informacion, hallazgos


def obtener_defender_avanzado_windows() -> tuple[list[str], list[str]]:
    """Amplía la revisión de Defender con exclusiones y protección frente a manipulaciones."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar Microsoft Defender en profundidad"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_preferencias = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$p=Get-MpPreference; $p | Select-Object DisableRealtimeMonitoring,TamperProtection,ExclusionPath,ExclusionProcess | Format-List",
    ]
    _, salida = ejecutar_comando_seguro(comando_preferencias, timeout=20)
    informacion.extend([f"Defender avanzado: {linea}" for linea in resumir_lineas(salida, 12)])
    salida_minuscula = salida.lower()
    if "disablerealtimemonitoring : true" in salida_minuscula:
        hallazgos.append("[ALTO] La supervisión en tiempo real de Defender aparece desactivada")
    if "tamperprotection : 0" in salida_minuscula or "tamperprotection : false" in salida_minuscula:
        hallazgos.append("[MEDIO] La protección frente a manipulaciones de Defender parece desactivada")
    if re.search(r"exclusion(path|process)\s*:\s*(?!\{\})(?!$).+", salida_minuscula):
        hallazgos.append("[MEDIO] Existen exclusiones configuradas en Microsoft Defender; revise su necesidad")

    return informacion, hallazgos


def obtener_firma_smb_windows() -> tuple[list[str], list[str]]:
    """Consulta la configuración de firma SMB del cliente y servidor en Windows."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar la firma SMB"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comandos = [
        (
            ["powershell", "-NoProfile", "-Command", "Get-SmbServerConfiguration | Select-Object EnableSecuritySignature,RequireSecuritySignature | Format-List"],
            "SMB servidor",
        ),
        (
            ["powershell", "-NoProfile", "-Command", "Get-SmbClientConfiguration | Select-Object EnableSecuritySignature,RequireSecuritySignature | Format-List"],
            "SMB cliente",
        ),
    ]

    for comando, etiqueta in comandos:
        _, salida = ejecutar_comando_seguro(comando, timeout=20)
        informacion.extend([f"{etiqueta}: {linea}" for linea in resumir_lineas(salida, 6)])
        salida_minuscula = salida.lower()
        if "requiresecuritysignature : false" in salida_minuscula:
            hallazgos.append(f"[MEDIO] {etiqueta} no requiere firma SMB")

    return informacion, hallazgos


def obtener_politicas_auditoria_windows() -> tuple[list[str], list[str]]:
    """Consulta la política de auditoría de Windows para identificar categorías sin registro."""
    if not shutil.which("auditpol"):
        return ["No se encontró auditpol para consultar la política de auditoría"], []

    _, salida = ejecutar_comando_seguro(["auditpol", "/get", "/category:*"] , timeout=25)
    lineas = [linea.strip() for linea in salida.splitlines() if linea.strip()]
    informacion = ["Política de auditoría (muestra):"] + resumir_lineas("\n".join(lineas), 16)
    hallazgos: list[str] = []

    sin_auditoria = [linea for linea in lineas if "no auditing" in linea.lower() or "sin auditoría" in linea.lower()]
    if sin_auditoria:
        hallazgos.append(f"[MEDIO] Se detectaron {len(sin_auditoria)} subcategorías sin auditoría configurada")

    categorias_criticas = ["Logon", "Credential Validation", "Account Lockout", "Special Logon"]
    for categoria in categorias_criticas:
        coincidencia = next((linea for linea in lineas if categoria.lower() in linea.lower()), "")
        if coincidencia and ("no auditing" in coincidencia.lower() or "sin auditoría" in coincidencia.lower()):
            hallazgos.append(f"[ALTO] La subcategoría crítica de auditoría '{categoria}' no registra eventos")

    return informacion, hallazgos


def obtener_laps_windows() -> tuple[list[str], list[str]]:
    """Busca indicios de configuración de Windows LAPS o Microsoft LAPS en el host local."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar LAPS"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_laps = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$r1='HKLM:\\SOFTWARE\\Microsoft\\Policies\\LAPS'; $r2='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config'; "
        "if (Test-Path $r1) {Get-ItemProperty $r1 | Format-List} elseif (Test-Path $r2) {Get-ItemProperty $r2 | Format-List} else {'LAPS_NO_CONFIG'}",
    ]
    _, salida = ejecutar_comando_seguro(comando_laps, timeout=20)

    if "LAPS_NO_CONFIG" in salida:
        informacion.append("LAPS: no se detectó configuración local")
        hallazgos.append("[MEDIO] No se detectó configuración local de LAPS")
        return informacion, hallazgos

    informacion.extend(["LAPS / Microsoft LAPS:"] + resumir_lineas(salida, 10))
    salida_minuscula = salida.lower()
    if "backupdirectory" in salida_minuscula:
        hallazgos.append("[INFO] Se detectó configuración local relacionada con LAPS")

    return informacion, hallazgos


def obtener_logging_powershell_windows() -> tuple[list[str], list[str]]:
    """Revisa si existen políticas de logging para PowerShell y transcripción."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para revisar su propio logging"], []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$bases=@(" \
        "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'," \
        "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging'," \
        "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription'" \
        "); " \
        "foreach ($b in $bases) { if (Test-Path $b) { \"[$b]\"; Get-ItemProperty $b | Format-List } }; " \
        "if (-not ($bases | Where-Object { Test-Path $_ })) { 'POWERSHELL_LOGGING_NO_CONFIG' }",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=20)

    informacion: list[str] = []
    hallazgos: list[str] = []
    if "POWERSHELL_LOGGING_NO_CONFIG" in salida:
        informacion.append("PowerShell logging: no se detectó política local explícita")
        hallazgos.append("[MEDIO] No se detectó configuración local de logging de PowerShell")
        return informacion, hallazgos

    informacion.extend(["PowerShell logging:"] + resumir_lineas(salida, 12))
    salida_minuscula = salida.lower()
    if "enablescriptblocklogging" not in salida_minuscula:
        hallazgos.append("[MEDIO] No se aprecia configuración de Script Block Logging")
    if "enablemodulelogging" not in salida_minuscula:
        hallazgos.append("[MEDIO] No se aprecia configuración de Module Logging")
    if "enabletranscripting" not in salida_minuscula:
        hallazgos.append("[MEDIO] No se aprecia configuración de transcripción de PowerShell")

    return informacion, hallazgos


def obtener_firewall_perfiles_windows() -> tuple[list[str], list[str]]:
    """Obtiene detalles útiles por perfil del firewall de Windows más allá del estado básico."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar perfiles avanzados del firewall"], []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules | Format-Table -HideTableHeaders",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=20)
    informacion = ["Perfiles del firewall (muestra):"] + resumir_lineas(salida, 10)
    hallazgos: list[str] = []
    salida_minuscula = salida.lower()
    if re.search(r"\ballow\b", salida_minuscula):
        hallazgos.append("[MEDIO] Revise los perfiles del firewall: se observaron acciones de entrada permisivas")
    if re.search(r"\bfalse\b", salida_minuscula):
        hallazgos.append("[ALTO] Algún perfil del firewall aparece deshabilitado")
    return informacion, hallazgos


def obtener_eventos_criticos_windows() -> tuple[list[str], list[str]]:
    """Recoge un resumen de eventos críticos y de error recientes en Windows."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar eventos críticos"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-3); Level=1,2} "
        "-MaxEvents 8 | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message | Format-Table -Wrap -HideTableHeaders",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=30)

    if salida.strip():
        informacion.extend(["Eventos críticos recientes del sistema:"] + resumir_lineas(salida, 12))
        eventos = [linea for linea in salida.splitlines() if linea.strip()]
        if len(eventos) >= 5:
            hallazgos.append("[MEDIO] Se detectaron varios eventos críticos o de error recientes en el sistema")
    else:
        informacion.append("No se recuperaron eventos críticos recientes del sistema")

    return informacion, hallazgos


def obtener_lsa_y_credential_guard_windows() -> tuple[list[str], list[str]]:
    """Comprueba protecciones de credenciales como LSA Protection y Credential Guard."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar protecciones de credenciales"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_lsa = [
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL",
    ]
    _, salida_lsa = ejecutar_comando_seguro(comando_lsa, timeout=10)
    if salida_lsa.strip() == "1":
        informacion.append("LSA Protection: habilitada")
    elif salida_lsa.strip() == "0":
        informacion.append("LSA Protection: deshabilitada")
        hallazgos.append("[MEDIO] LSA Protection aparece deshabilitada")
    else:
        informacion.append("LSA Protection: no se pudo determinar")

    comando_cg = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object SecurityServicesConfigured,SecurityServicesRunning,VirtualizationBasedSecurityStatus | Format-List",
    ]
    _, salida_cg = ejecutar_comando_seguro(comando_cg, timeout=20)
    if salida_cg.strip():
        informacion.extend(["Device Guard / Credential Guard:"] + resumir_lineas(salida_cg, 10))
        salida_minuscula = salida_cg.lower()
        if "securityservicesrunning" in salida_minuscula and "1" not in salida_minuscula:
            hallazgos.append("[MEDIO] No se observa Credential Guard en ejecución")

    return informacion, hallazgos


def obtener_applocker_y_wdac_windows() -> tuple[list[str], list[str]]:
    """Consulta controles de lista blanca como AppLocker y la presencia de políticas WDAC."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar AppLocker o WDAC"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_applocker = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-Service AppIDSvc -ErrorAction SilentlyContinue | Select-Object Status,StartType | Format-List",
    ]
    _, salida_applocker = ejecutar_comando_seguro(comando_applocker, timeout=15)
    if salida_applocker.strip():
        informacion.extend(["AppLocker (servicio AppIDSvc):"] + resumir_lineas(salida_applocker, 6))
        if "stopped" in salida_applocker.lower():
            hallazgos.append("[MEDIO] AppLocker no parece estar activo")
    else:
        informacion.append("AppLocker: no se pudo obtener el estado del servicio")

    comando_wdac = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$ruta='C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active'; if (Test-Path $ruta) {(Get-ChildItem $ruta | Measure-Object).Count} else {'0'}",
    ]
    _, salida_wdac = ejecutar_comando_seguro(comando_wdac, timeout=15)
    if salida_wdac.strip().isdigit():
        cantidad = int(salida_wdac.strip())
        informacion.append(f"WDAC / Code Integrity policies activas: {cantidad}")
        if cantidad == 0:
            hallazgos.append("[MEDIO] No se detectaron políticas WDAC activas")

    return informacion, hallazgos


def obtener_reglas_firewall_entrada_windows() -> tuple[list[str], list[str]]:
    """Resume reglas de entrada permitidas para detectar exposición amplia en el firewall de Windows."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar reglas del firewall"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_cuenta = [
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Measure-Object).Count",
    ]
    _, salida_cuenta = ejecutar_comando_seguro(comando_cuenta, timeout=20)
    if salida_cuenta.strip().isdigit():
        cantidad = int(salida_cuenta.strip())
        informacion.append(f"Reglas inbound permitidas activas: {cantidad}")
        if cantidad > 60:
            hallazgos.append("[MEDIO] Existe un número elevado de reglas de entrada permitidas")

    comando_muestra = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Select-Object -First 8 DisplayName,Profile | Format-Table -HideTableHeaders",
    ]
    _, salida_muestra = ejecutar_comando_seguro(comando_muestra, timeout=20)
    if salida_muestra.strip():
        informacion.extend(["Reglas inbound permitidas (muestra):"] + resumir_lineas(salida_muestra, 10))

    return informacion, hallazgos


def obtener_smartscreen_windows() -> tuple[list[str], list[str]]:
    """Consulta el estado básico de SmartScreen y controles de reputación en Windows."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar SmartScreen"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comandos = [
        (
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled",
            ],
            "SmartScreen Explorer",
        ),
        (
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name EnableSmartScreen -ErrorAction SilentlyContinue).EnableSmartScreen",
            ],
            "SmartScreen política",
        ),
    ]

    for comando, etiqueta in comandos:
        _, salida = ejecutar_comando_seguro(comando, timeout=10)
        if salida.strip():
            informacion.append(f"{etiqueta}: {salida.strip()}")

    texto = " ".join(informacion).lower()
    if "off" in texto or "warn" not in texto and "block" not in texto and "1" not in texto:
        hallazgos.append("[MEDIO] No se pudo confirmar una configuración fuerte de SmartScreen")

    if not informacion:
        informacion.append("No se obtuvo información concluyente de SmartScreen")

    return informacion, hallazgos


def obtener_politica_powershell_windows() -> tuple[list[str], list[str]]:
    """Obtiene las políticas de ejecución de PowerShell configuradas por ámbito."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar Execution Policy"], []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-ExecutionPolicy -List | Format-Table -HideTableHeaders",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=15)
    informacion = ["Execution Policy de PowerShell:"] + resumir_lineas(salida, 10)
    hallazgos: list[str] = []
    salida_minuscula = salida.lower()
    if "bypass" in salida_minuscula or "unrestricted" in salida_minuscula:
        hallazgos.append("[MEDIO] Se detectó una Execution Policy permisiva en PowerShell")
    elif "restricted" in salida_minuscula or "remotesigned" in salida_minuscula or "allsigned" in salida_minuscula:
        hallazgos.append("[INFO] Se detectó una política de ejecución más restrictiva en PowerShell")
    return informacion, hallazgos


def obtener_sesiones_recientes_windows() -> tuple[list[str], list[str]]:
    """Resume sesiones de usuario activas o recientes para facilitar revisión operativa."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    if shutil.which("quser"):
        _, salida_quser = ejecutar_comando_seguro(["quser"], timeout=10)
        if salida_quser.strip():
            informacion.extend(["Sesiones de usuario (quser):"] + resumir_lineas(salida_quser, 8))

    if shutil.which("powershell"):
        comando_eventos = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 6 | "
            "ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' | ' + $_.Properties[5].Value + ' | LogonType=' + $_.Properties[8].Value }",
        ]
        _, salida_eventos = ejecutar_comando_seguro(comando_eventos, timeout=25)
        if salida_eventos.strip():
            informacion.extend(["Inicios de sesión recientes (muestra):"] + resumir_lineas(salida_eventos, 8))

    if not informacion:
        informacion.append("No se pudo obtener información de sesiones recientes")

    return informacion, hallazgos


def obtener_reglas_firewall_peligrosas_windows() -> tuple[list[str], list[str]]:
    """Busca reglas de entrada muy permisivas que merecen una revisión manual."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para revisar reglas peligrosas del firewall"], []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
        "Get-NetFirewallAddressFilter | Where-Object { $_.RemoteAddress -eq 'Any' } | "
        "Select-Object -First 8 Name,RemoteAddress | Format-Table -HideTableHeaders",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=25)
    informacion: list[str] = []
    hallazgos: list[str] = []
    if salida.strip():
        informacion.extend(["Reglas inbound con RemoteAddress=Any (muestra):"] + resumir_lineas(salida, 10))
        hallazgos.append("[MEDIO] Existen reglas inbound habilitadas expuestas a cualquier origen")
    else:
        informacion.append("No se detectaron reglas inbound abiertas a cualquier origen en la muestra")

    return informacion, hallazgos


def obtener_proteccion_ransomware_defender_windows() -> tuple[list[str], list[str]]:
    """Consulta la protección frente a ransomware de Microsoft Defender."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar la protección contra ransomware"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-MpPreference | Select-Object EnableControlledFolderAccess, ControlledFolderAccessProtectedFolders, ControlledFolderAccessAllowedApplications | Format-List",
    ]
    _, salida = ejecutar_comando_seguro(comando, timeout=25)
    informacion.extend(["Protección contra ransomware (Defender):"] + resumir_lineas(salida, 12))
    salida_minuscula = salida.lower()

    if "enablecontrolledfolderaccess : 0" in salida_minuscula:
        hallazgos.append("[MEDIO] Controlled Folder Access de Defender aparece deshabilitado")
    elif "enablecontrolledfolderaccess : 1" in salida_minuscula or "enablecontrolledfolderaccess : 2" in salida_minuscula:
        hallazgos.append("[INFO] Controlled Folder Access de Defender aparece habilitado o en modo auditoría")

    return informacion, hallazgos


def obtener_remote_assistance_windows() -> tuple[list[str], list[str]]:
    """Revisa la configuración de Remote Assistance en Windows."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar Remote Assistance"], []

    informacion: list[str] = []
    hallazgos: list[str] = []
    comandos = [
        (
            "Asistencia remota solicitada",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' -Name fAllowToGetHelp -ErrorAction SilentlyContinue).fAllowToGetHelp",
        ),
        (
            "Asistencia remota ofrecida",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' -Name fAllowFullControl -ErrorAction SilentlyContinue).fAllowFullControl",
        ),
    ]

    for etiqueta, expresion in comandos:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=10)
        if salida.strip() != "":
            informacion.append(f"{etiqueta}: {salida.strip()}")
            if salida.strip() == "1":
                hallazgos.append(f"[MEDIO] {etiqueta} aparece habilitada")

    if not informacion:
        informacion.append("No se pudo obtener la configuración de Remote Assistance")

    return informacion, hallazgos


def obtener_servicios_automaticos_inusuales_windows() -> tuple[list[str], list[str]]:
    """Detecta servicios automáticos en ejecución con rutas inusuales o firma no válida."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para revisar servicios automáticos"], []

    script = (
        "$servicios = Get-CimInstance Win32_Service | "
        "Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.PathName }; "
        "$resultados = foreach ($s in $servicios) { "
        "  $ruta = $s.PathName -replace '^\"','' -replace '\".*$',''; "
        "  $ruta = $ruta.Split(' ')[0]; "
        "  $firma = 'No comprobada'; "
        "  if (Test-Path $ruta) { "
        "    try { $firma = (Get-AuthenticodeSignature $ruta).Status } catch { $firma = 'ErrorFirma' } "
        "  } "
        "  [PSCustomObject]@{ Name=$s.Name; StartName=$s.StartName; Path=$ruta; Firma=$firma } "
        "}; "
        "$resultados | Where-Object { $_.Firma -ne 'Valid' -or $_.Path -match 'Users|ProgramData|Temp' } | "
        "Select-Object -First 12 Name, StartName, Firma, Path | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=35)

    informacion: list[str] = []
    hallazgos: list[str] = []
    if salida.strip():
        informacion.extend(["Servicios automáticos inusuales o no firmados (muestra):"] + resumir_lineas(salida, 14))
        hallazgos.append("[MEDIO] Se detectaron servicios automáticos con firma no válida o rutas poco habituales")
    else:
        informacion.append("No se detectaron en la muestra servicios automáticos no firmados o con rutas inusuales")

    return informacion, hallazgos


def obtener_software_potencialmente_obsoleto_windows() -> tuple[list[str], list[str]]:
    """Obtiene software instalado y marca productos típicamente desactualizados o de alto riesgo."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar software instalado"], []

    script = (
        "$rutas = @(" \
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'," \
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'" \
        "); " \
        "Get-ItemProperty $rutas -ErrorAction SilentlyContinue | " \
        "Where-Object { $_.DisplayName -and $_.DisplayVersion } | " \
        "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=40)

    informacion: list[str] = []
    hallazgos: list[str] = []
    if salida.strip():
        informacion.extend(["Software instalado (muestra):"] + resumir_lineas(salida, 16))

    patrones_riesgo = {
        r"java\s+8|jre\s+8|jdk\s+8": "[MEDIO] Se detectó una versión antigua de Java 8; revise soporte y parches",
        r"python\s+2\.|python\s+2$": "[ALTO] Se detectó Python 2, tecnología obsoleta y sin soporte",
        r"adobe\s+reader\s+(9|x|xi)": "[MEDIO] Se detectó una versión antigua de Adobe Reader",
        r"flash": "[ALTO] Se detectó software relacionado con Adobe Flash, obsoleto e inseguro",
        r"silverlight": "[ALTO] Se detectó Microsoft Silverlight, obsoleto",
        r"internet\s+explorer": "[ALTO] Se detectó Internet Explorer, tecnología obsoleta",
        r"office\s+2010|office\s+2013": "[MEDIO] Se detectó una versión antigua de Microsoft Office",
        r"\.net.*4\.5|\.net.*4\.0|\.net.*4\.6": "[MEDIO] Se detectó una versión antigua de .NET Framework",
    }

    salida_minuscula = salida.lower()
    for patron, mensaje in patrones_riesgo.items():
        if re.search(patron, salida_minuscula):
            hallazgos.append(mensaje)

    if not informacion:
        informacion.append("No se pudo obtener el inventario de software instalado")

    return informacion, hallazgos


def obtener_autologon_windows() -> tuple[list[str], list[str]]:
    """Revisa si el inicio de sesión automático está configurado en el equipo."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar AutoAdminLogon"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$clave = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue; "
        "[PSCustomObject]@{ "
        "  AutoAdminLogon = $clave.AutoAdminLogon; "
        "  DefaultUserName = $clave.DefaultUserName; "
        "  DefaultDomainName = $clave.DefaultDomainName "
        "} | Format-List"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=15)
    informacion.extend(["Inicio de sesión automático:"] + resumir_lineas(salida, 8))

    salida_minuscula = salida.lower()
    if "autoadminlogon : 1" in salida_minuscula:
        hallazgos.append("[ALTO] AutoAdminLogon aparece habilitado; podría existir almacenamiento de credenciales locales")
    elif "autoadminlogon : 0" in salida_minuscula:
        hallazgos.append("[INFO] AutoAdminLogon aparece deshabilitado")

    return informacion, hallazgos


def obtener_always_install_elevated_windows() -> tuple[list[str], list[str]]:
    """Comprueba la directiva AlwaysInstallElevated en HKLM y HKCU."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar AlwaysInstallElevated"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comprobaciones = [
        (
            "HKLM AlwaysInstallElevated",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated",
        ),
        (
            "HKCU AlwaysInstallElevated",
            "(Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated",
        ),
    ]

    valores: dict[str, str] = {}
    for etiqueta, expresion in comprobaciones:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=10)
        valor = salida.strip() or "No configurado"
        valores[etiqueta] = valor
        informacion.append(f"{etiqueta}: {valor}")

    if valores.get("HKLM AlwaysInstallElevated") == "1" and valores.get("HKCU AlwaysInstallElevated") == "1":
        hallazgos.append("[ALTO] AlwaysInstallElevated está habilitado en HKLM y HKCU; permite elevación peligrosa mediante MSI")
    elif "1" in valores.values():
        hallazgos.append("[MEDIO] AlwaysInstallElevated aparece habilitado parcialmente; revise la directiva")
    else:
        hallazgos.append("[INFO] No se detectó AlwaysInstallElevated habilitado")

    return informacion, hallazgos


def obtener_autenticacion_legacy_windows() -> tuple[list[str], list[str]]:
    """Revisa controles de autenticación heredada como WDigest, LLMNR y compatibilidad NTLM."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar autenticación heredada"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    consultas = [
        (
            "WDigest UseLogonCredential",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential",
        ),
        (
            "LLMNR EnableMulticast",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast",
        ),
        (
            "LMCompatibilityLevel",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LMCompatibilityLevel -ErrorAction SilentlyContinue).LMCompatibilityLevel",
        ),
    ]

    valores: dict[str, str] = {}
    for etiqueta, expresion in consultas:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=10)
        valor = salida.strip() or "No configurado"
        valores[etiqueta] = valor
        informacion.append(f"{etiqueta}: {valor}")

    if valores.get("WDigest UseLogonCredential") == "1":
        hallazgos.append("[ALTO] WDigest permite almacenar credenciales reutilizables en memoria")

    valor_llmnr = valores.get("LLMNR EnableMulticast", "")
    if valor_llmnr == "1":
        hallazgos.append("[MEDIO] LLMNR aparece habilitado; aumenta el riesgo de envenenamiento de resolución de nombres")
    elif valor_llmnr == "0":
        hallazgos.append("[INFO] LLMNR aparece deshabilitado")

    valor_ntlm = valores.get("LMCompatibilityLevel", "")
    if valor_ntlm.isdigit():
        nivel_ntlm = int(valor_ntlm)
        if nivel_ntlm < 5:
            hallazgos.append("[MEDIO] LMCompatibilityLevel es bajo; podrían permitirse esquemas NTLM menos robustos")
        else:
            hallazgos.append("[INFO] LMCompatibilityLevel parece restrictivo")

    return informacion, hallazgos


def obtener_protocolos_tls_windows() -> tuple[list[str], list[str]]:
    """Consulta si TLS 1.0/1.1 siguen habilitados y si .NET fuerza criptografía fuerte."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar protocolos TLS"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    consultas = [
        (
            "TLS 1.0 cliente Enabled",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client' -Name Enabled -ErrorAction SilentlyContinue).Enabled",
        ),
        (
            "TLS 1.0 servidor Enabled",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name Enabled -ErrorAction SilentlyContinue).Enabled",
        ),
        (
            "TLS 1.1 cliente Enabled",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client' -Name Enabled -ErrorAction SilentlyContinue).Enabled",
        ),
        (
            "TLS 1.1 servidor Enabled",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name Enabled -ErrorAction SilentlyContinue).Enabled",
        ),
        (
            ".NET SchUseStrongCrypto",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue).SchUseStrongCrypto",
        ),
        (
            ".NET SchUseStrongCrypto WOW64",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue).SchUseStrongCrypto",
        ),
    ]

    valores: dict[str, str] = {}
    for etiqueta, expresion in consultas:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=10)
        valor = salida.strip() or "No configurado"
        valores[etiqueta] = valor
        informacion.append(f"{etiqueta}: {valor}")

    for clave, valor in valores.items():
        clave_minuscula = clave.lower()
        if "tls 1.0" in clave_minuscula or "tls 1.1" in clave_minuscula:
            if valor == "1":
                hallazgos.append(f"[MEDIO] {clave} aparece habilitado")
        if "schusestrongcrypto" in clave_minuscula and valor == "0":
            hallazgos.append(f"[MEDIO] {clave} aparece deshabilitado; .NET podría permitir criptografía más débil")

    return informacion, hallazgos


def obtener_persistencia_inicio_windows() -> tuple[list[str], list[str]]:
    """Busca mecanismos comunes de persistencia en Run y RunOnce para revisión manual."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar persistencia de inicio"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$rutas = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
        "); "
        "$salida = foreach ($ruta in $rutas) { "
        "  if (Test-Path $ruta) { "
        "    $propiedades = Get-ItemProperty $ruta; "
        "    foreach ($propiedad in $propiedades.PSObject.Properties) { "
        "      if ($propiedad.Name -notmatch '^PS') { "
        "        [PSCustomObject]@{ Ruta=$ruta; Nombre=$propiedad.Name; Valor=$propiedad.Value } "
        "      } "
        "    } "
        "  } "
        "}; "
        "$salida | Select-Object -First 14 Ruta, Nombre, Valor | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=30)

    if salida.strip():
        informacion.extend(["Persistencia en Run/RunOnce (muestra):"] + resumir_lineas(salida, 16))
        salida_minuscula = salida.lower()
        if re.search(r"appdata|programdata|temp|users\\", salida_minuscula):
            hallazgos.append("[MEDIO] Existen entradas de inicio automático ubicadas en rutas de usuario o temporales")
        if re.search(r"powershell|wscript|cscript|cmd\.exe|rundll32|mshta", salida_minuscula):
            hallazgos.append("[MEDIO] Se detectaron comandos de inicio automático con intérpretes o binarios de uso sensible")
    else:
        informacion.append("No se detectaron entradas de persistencia en Run/RunOnce en la muestra")

    return informacion, hallazgos


def obtener_proxy_y_dns_windows() -> tuple[list[str], list[str]]:
    """Resume configuración de proxy y DNS para identificar exposiciones o desvíos."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar proxy y DNS"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_proxy = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | Format-List",
    ]
    _, salida_proxy = ejecutar_comando_seguro(comando_proxy, timeout=15)
    if salida_proxy.strip():
        informacion.extend(["Configuración de proxy:"] + resumir_lineas(salida_proxy, 8))
        if "proxyenable : 1" in salida_proxy.lower():
            hallazgos.append("[INFO] Existe un proxy configurado en el perfil de usuario actual")

    comando_dns = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -First 10 InterfaceAlias,ServerAddresses | Format-Table -Wrap -HideTableHeaders",
    ]
    _, salida_dns = ejecutar_comando_seguro(comando_dns, timeout=20)
    if salida_dns.strip():
        informacion.extend(["Servidores DNS configurados (muestra):"] + resumir_lineas(salida_dns, 12))
        salida_dns_minuscula = salida_dns.lower()
        if re.search(r"\b8\.8\.8\.8\b|\b1\.1\.1\.1\b|\b9\.9\.9\.9\b", salida_dns_minuscula):
            hallazgos.append("[INFO] Se detectaron resolutores DNS públicos; confirme que están autorizados por la organización")

    if not informacion:
        informacion.append("No se pudo obtener información de proxy o DNS")

    return informacion, hallazgos


def obtener_certificados_windows() -> tuple[list[str], list[str]]:
    """Revisa certificados del almacén local para detectar expirados o próximos a caducar."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar certificados locales"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$certs = Get-ChildItem Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue; "
        "$proximos = $certs | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }; "
        "$expirados = $certs | Where-Object { $_.NotAfter -lt (Get-Date) }; "
        "Write-Output ('Total certificados LM\\My: ' + ($certs | Measure-Object).Count); "
        "Write-Output ('Certificados próximos a caducar (<30 días): ' + ($proximos | Measure-Object).Count); "
        "Write-Output ('Certificados expirados: ' + ($expirados | Measure-Object).Count); "
        "$certs | Select-Object -First 8 Subject, NotAfter, Thumbprint | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=25)

    if salida.strip():
        informacion.extend(["Certificados del almacén local (muestra):"] + resumir_lineas(salida, 14))
        coincidencia_expirados = re.search(r"certificados expirados:\s*(\d+)", salida.lower())
        coincidencia_proximos = re.search(r"próximos a caducar \(<30 días\):\s*(\d+)", salida.lower())
        if coincidencia_expirados and int(coincidencia_expirados.group(1)) > 0:
            hallazgos.append(f"[MEDIO] Se detectaron {coincidencia_expirados.group(1)} certificados expirados en LocalMachine\\My")
        if coincidencia_proximos and int(coincidencia_proximos.group(1)) > 0:
            hallazgos.append(f"[MEDIO] Se detectaron {coincidencia_proximos.group(1)} certificados próximos a caducar en LocalMachine\\My")
    else:
        informacion.append("No se pudo obtener información del almacén de certificados local")

    return informacion, hallazgos


def obtener_software_acceso_remoto_windows() -> tuple[list[str], list[str]]:
    """Busca software y servicios de acceso remoto de terceros instalados en el equipo."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar software de acceso remoto"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script_software = (
        "$patron = 'TeamViewer|AnyDesk|RustDesk|VNC|UltraVNC|TightVNC|RealVNC|LogMeIn|GoToMyPC|ScreenConnect|ConnectWise|Radmin|AeroAdmin|Ammyy'; "
        "$rutas = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
        "Get-ItemProperty $rutas -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $patron } | "
        "Select-Object -First 12 DisplayName, DisplayVersion, Publisher | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida_software = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_software], timeout=35)
    if salida_software.strip():
        informacion.extend(["Software de acceso remoto detectado (muestra):"] + resumir_lineas(salida_software, 14))
        hallazgos.append("[MEDIO] Se detectó software de acceso remoto de terceros; confirme necesidad y endurecimiento")

    script_servicios = (
        "$patron = 'TeamViewer|AnyDesk|RustDesk|VNC|LogMeIn|ScreenConnect|ConnectWise|Radmin'; "
        "Get-CimInstance Win32_Service | Where-Object { $_.Name -match $patron -or $_.DisplayName -match $patron } | "
        "Select-Object -First 10 Name, State, StartMode, StartName | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida_servicios = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_servicios], timeout=30)
    if salida_servicios.strip():
        informacion.extend(["Servicios de acceso remoto detectados (muestra):"] + resumir_lineas(salida_servicios, 12))

    if not informacion:
        informacion.append("No se detectó software de acceso remoto de terceros en la muestra")

    return informacion, hallazgos


def obtener_tareas_sospechosas_windows() -> tuple[list[str], list[str]]:
    """Detecta tareas programadas con intérpretes o rutas que merecen revisión."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para revisar tareas programadas sospechosas"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$tareas = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "
        "  foreach ($accion in $_.Actions) { "
        "    [PSCustomObject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; Execute=$accion.Execute; Arguments=$accion.Arguments } "
        "  } "
        "}; "
        "$tareas | Where-Object { "
        "  $_.Execute -match 'powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|regsvr32' -or "
        "  $_.Execute -match 'Users|AppData|ProgramData|Temp' -or $_.Arguments -match 'FromBase64String|EncodedCommand' "
        "} | Select-Object -First 12 TaskPath, TaskName, Execute, Arguments | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=35)

    if salida.strip():
        informacion.extend(["Tareas programadas sospechosas (muestra):"] + resumir_lineas(salida, 16))
        hallazgos.append("[MEDIO] Existen tareas programadas con intérpretes, rutas de usuario o argumentos sensibles")
    else:
        informacion.append("No se detectaron tareas programadas sospechosas en la muestra")

    return informacion, hallazgos


def obtener_politicas_navegador_windows() -> tuple[list[str], list[str]]:
    """Revisa algunas políticas de Edge y Chrome relacionadas con sincronización, contraseñas y extensiones forzadas."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar políticas de navegador"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    consultas = [
        (
            "Edge PasswordManagerEnabled",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name PasswordManagerEnabled -ErrorAction SilentlyContinue).PasswordManagerEnabled",
        ),
        (
            "Edge SyncDisabled",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name SyncDisabled -ErrorAction SilentlyContinue).SyncDisabled",
        ),
        (
            "Chrome PasswordManagerEnabled",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name PasswordManagerEnabled -ErrorAction SilentlyContinue).PasswordManagerEnabled",
        ),
        (
            "Chrome SyncDisabled",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name SyncDisabled -ErrorAction SilentlyContinue).SyncDisabled",
        ),
    ]

    for etiqueta, expresion in consultas:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=10)
        if salida.strip():
            informacion.append(f"{etiqueta}: {salida.strip()}")

    script_extensiones = (
        "$rutas = @('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist','HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist'); "
        "foreach ($ruta in $rutas) { if (Test-Path $ruta) { Get-ItemProperty $ruta | Format-List } }"
    )
    _, salida_extensiones = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_extensiones], timeout=15)
    if salida_extensiones.strip():
        informacion.extend(["Extensiones forzadas por política (muestra):"] + resumir_lineas(salida_extensiones, 12))
        hallazgos.append("[INFO] Existen extensiones de navegador instaladas por política; conviene revisar su legitimidad")

    texto = " ".join(informacion).lower()
    if "passwordmanagerenabled: 1" in texto or "passwordmanagerenabled: true" in texto:
        hallazgos.append("[INFO] Algún navegador permite el gestor de contraseñas integrado por política")

    if not informacion:
        informacion.append("No se detectaron políticas relevantes de Edge o Chrome en el ámbito revisado")

    return informacion, hallazgos


def obtener_permisos_smb_windows() -> tuple[list[str], list[str]]:
    """Revisa permisos de comparticiones SMB para detectar accesos amplios tipo Everyone o Guest."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar permisos SMB"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$comparticiones = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN\\$|C\\$|IPC\\$|PRINT\\$)$' }; "
        "$salida = foreach ($c in $comparticiones) { "
        "  Get-SmbShareAccess -Name $c.Name -ErrorAction SilentlyContinue | "
        "  Select-Object @{N='Share';E={$c.Name}}, AccountName, AccessControlType, AccessRight "
        "}; "
        "$salida | Select-Object -First 14 Share, AccountName, AccessControlType, AccessRight | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=30)

    if salida.strip():
        informacion.extend(["Permisos de comparticiones SMB (muestra):"] + resumir_lineas(salida, 16))
        salida_minuscula = salida.lower()
        if "everyone" in salida_minuscula or "todos" in salida_minuscula:
            hallazgos.append("[MEDIO] Alguna compartición SMB parece conceder acceso a Everyone/Todos")
        if "guest" in salida_minuscula or "invitado" in salida_minuscula:
            hallazgos.append("[ALTO] Alguna compartición SMB parece conceder acceso a Guest/Invitado")
        if "full" in salida_minuscula or "change" in salida_minuscula:
            hallazgos.append("[INFO] Existen permisos SMB amplios en la muestra; revise si son necesarios")
    else:
        informacion.append("No se pudieron obtener permisos detallados de comparticiones SMB")

    return informacion, hallazgos


def obtener_eventos_altas_privilegios_windows() -> tuple[list[str], list[str]]:
    """Resume eventos recientes de creación de usuarios y cambios en grupos privilegiados."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar eventos de altas y privilegios"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$ids = 4720,4722,4728,4732,4756; "
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 12 | "
        "ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' | ID=' + $_.Id + ' | ' + $_.Message.Split([Environment]::NewLine)[0] }"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=35)

    if salida.strip():
        informacion.extend(["Eventos recientes de cuentas y privilegios:"] + resumir_lineas(salida, 14))
        hallazgos.append("[INFO] Se registraron eventos recientes relacionados con cuentas o grupos privilegiados; conviene revisarlos")
    else:
        informacion.append("No se obtuvieron eventos recientes de altas de usuarios o cambios de grupos privilegiados")

    return informacion, hallazgos


def obtener_dispositivos_usb_windows() -> tuple[list[str], list[str]]:
    """Revisa política USBSTOR e historial básico de dispositivos USB conectados."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar dispositivos USB"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_usbstor = [
        "powershell",
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -ErrorAction SilentlyContinue).Start",
    ]
    _, salida_usbstor = ejecutar_comando_seguro(comando_usbstor, timeout=10)
    if salida_usbstor.strip():
        informacion.append(f"USBSTOR Start: {salida_usbstor.strip()}")
        if salida_usbstor.strip() in {"3", "0", "1", "2"}:
            hallazgos.append("[INFO] El uso de almacenamiento USB parece permitido por configuración del servicio USBSTOR")
        elif salida_usbstor.strip() == "4":
            hallazgos.append("[INFO] El servicio USBSTOR aparece deshabilitado")

    script_dispositivos = (
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' -ErrorAction SilentlyContinue | "
        "Select-Object -First 12 FriendlyName, Mfg, DeviceDesc, Service | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida_dispositivos = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_dispositivos], timeout=25)
    if salida_dispositivos.strip():
        informacion.extend(["Dispositivos USBSTOR detectados (muestra):"] + resumir_lineas(salida_dispositivos, 14))

    if not informacion:
        informacion.append("No se obtuvo información relevante sobre USBSTOR o dispositivos USB")

    return informacion, hallazgos


def obtener_perfiles_wifi_windows() -> tuple[list[str], list[str]]:
    """Lista perfiles Wi‑Fi guardados y resume el tipo de autenticación y cifrado."""
    if not shutil.which("netsh"):
        return ["No se encontró netsh para consultar perfiles Wi‑Fi"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    _, salida_perfiles = ejecutar_comando_seguro(["netsh", "wlan", "show", "profiles"], timeout=20)
    lineas_perfiles = [linea.strip() for linea in salida_perfiles.splitlines() if ":" in linea and "perfil" in linea.lower() or "profile" in linea.lower()]
    nombres_perfiles: list[str] = []
    for linea in lineas_perfiles:
        nombre = linea.split(":", 1)[-1].strip()
        if nombre and nombre not in nombres_perfiles:
            nombres_perfiles.append(nombre)

    if nombres_perfiles:
        informacion.append(f"Perfiles Wi‑Fi guardados: {', '.join(nombres_perfiles[:8])}")

    for nombre in nombres_perfiles[:5]:
        _, salida_detalle = ejecutar_comando_seguro(["netsh", "wlan", "show", "profile", f"name={nombre}"], timeout=20)
        lineas_detalle = []
        for linea in salida_detalle.splitlines():
            linea_limpia = linea.strip()
            if any(clave in linea_limpia.lower() for clave in ["authentication", "autenticación", "cipher", "cifrado", "cost"]):
                lineas_detalle.append(f"{nombre}: {linea_limpia}")
        informacion.extend(lineas_detalle[:6])
        texto_detalle = salida_detalle.lower()
        if "open" in texto_detalle or "abierta" in texto_detalle:
            hallazgos.append(f"[ALTO] El perfil Wi‑Fi '{nombre}' parece usar autenticación abierta")
        elif "wep" in texto_detalle:
            hallazgos.append(f"[ALTO] El perfil Wi‑Fi '{nombre}' parece usar WEP")
        elif "wpa" in texto_detalle and "wpa3" not in texto_detalle:
            hallazgos.append(f"[INFO] El perfil Wi‑Fi '{nombre}' usa WPA/WPA2; confirme alineación con la política corporativa")

    if not informacion:
        informacion.append("No se detectaron perfiles Wi‑Fi o no se pudo obtener su configuración")

    return informacion, hallazgos


def obtener_historial_rdp_windows() -> tuple[list[str], list[str]]:
    """Consulta rastros de conexiones RDP recientes y servidores almacenados en el usuario actual."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar historial RDP"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script_servidores = (
        "$ruta = 'HKCU:\\Software\\Microsoft\\Terminal Server Client\\Servers'; "
        "if (Test-Path $ruta) { Get-ChildItem $ruta | Select-Object -First 10 PSChildName | Format-Table -HideTableHeaders }"
    )
    _, salida_servidores = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_servidores], timeout=15)
    if salida_servidores.strip():
        informacion.extend(["Servidores RDP recordados (muestra):"] + resumir_lineas(salida_servidores, 10))
        hallazgos.append("[INFO] Existen destinos RDP almacenados en el perfil del usuario actual")

    script_eventos = (
        "Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 8 -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' | ID=' + $_.Id + ' | ' + $_.Message.Split([Environment]::NewLine)[0] }"
    )
    _, salida_eventos = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_eventos], timeout=25)
    if salida_eventos.strip():
        informacion.extend(["Eventos recientes de sesiones RDP:"] + resumir_lineas(salida_eventos, 10))

    if not informacion:
        informacion.append("No se obtuvo información de historial o eventos RDP")

    return informacion, hallazgos


def obtener_persistencia_winlogon_lsa_windows() -> tuple[list[str], list[str]]:
    """Revisa ubicaciones sensibles de persistencia en Winlogon, AppInit y paquetes LSA."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar persistencia Winlogon/LSA"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    consultas = [
        (
            "Winlogon Shell",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name Shell -ErrorAction SilentlyContinue).Shell",
        ),
        (
            "Winlogon Userinit",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name Userinit -ErrorAction SilentlyContinue).Userinit",
        ),
        (
            "AppInit_DLLs",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs",
        ),
        (
            "LoadAppInit_DLLs",
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs",
        ),
        (
            "LSA Security Packages",
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'Security Packages' -ErrorAction SilentlyContinue).'Security Packages'",
        ),
    ]

    for etiqueta, expresion in consultas:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=12)
        valor = salida.strip() or "No configurado"
        informacion.append(f"{etiqueta}: {valor}")

        valor_minuscula = valor.lower()
        if etiqueta == "Winlogon Shell" and valor and valor_minuscula not in {"explorer.exe", "no configurado"}:
            hallazgos.append("[ALTO] Winlogon Shell contiene un valor no estándar")
        if etiqueta == "Winlogon Userinit" and valor and "userinit.exe" not in valor_minuscula:
            hallazgos.append("[ALTO] Winlogon Userinit contiene un valor no estándar")
        if etiqueta == "AppInit_DLLs" and valor_minuscula not in {"", "no configurado"}:
            hallazgos.append("[ALTO] AppInit_DLLs contiene DLLs cargadas globalmente")
        if etiqueta == "LoadAppInit_DLLs" and valor == "1":
            hallazgos.append("[MEDIO] LoadAppInit_DLLs está habilitado")
        if etiqueta == "LSA Security Packages" and re.search(r"wdigest|tspkg|pku2u", valor_minuscula):
            hallazgos.append("[INFO] Revise la lista de paquetes LSA configurados")

    return informacion, hallazgos


def obtener_path_y_entorno_windows() -> tuple[list[str], list[str]]:
    """Revisa variables PATH de máquina y usuario buscando rutas peligrosas o inusuales."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar PATH y entorno"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    consultas = [
        ("PATH máquina", "[Environment]::GetEnvironmentVariable('Path','Machine')"),
        ("PATH usuario", "[Environment]::GetEnvironmentVariable('Path','User')"),
        ("PATHEXT", "[Environment]::GetEnvironmentVariable('PATHEXT','Machine')"),
    ]

    for etiqueta, expresion in consultas:
        _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", expresion], timeout=10)
        valor = salida.strip()
        if not valor:
            continue
        elementos = [parte.strip() for parte in valor.split(";") if parte.strip()]
        informacion.append(f"{etiqueta} (muestra):")
        informacion.extend([f"{etiqueta}: {linea}" for linea in elementos[:8]])
        texto_minuscula = " ; ".join(elementos).lower()
        if re.search(r"\\users\\|\\appdata\\|\\temp\\|\\public\\", texto_minuscula):
            hallazgos.append(f"[MEDIO] {etiqueta} contiene rutas de usuario o temporales")
        if ".js" in texto_minuscula or ".vbs" in texto_minuscula or ".ps1" in texto_minuscula:
            hallazgos.append(f"[INFO] {etiqueta} o PATHEXT incluye extensiones que conviene revisar en la política de ejecución")

    if not informacion:
        informacion.append("No se pudo obtener información de PATH o variables de entorno relevantes")

    return informacion, hallazgos


def obtener_exposicion_firewall_windows() -> tuple[list[str], list[str]]:
    """Resume reglas inbound por aplicación y puerto para identificar exposición directa."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar exposición del firewall"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script_puertos = (
        "$reglas = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
        "Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -and $_.LocalPort -ne 'Any' }; "
        "$reglas | Select-Object -First 12 Protocol, LocalPort, RemotePort, IcmpType | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida_puertos = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_puertos], timeout=30)
    if salida_puertos.strip():
        informacion.extend(["Puertos expuestos por reglas inbound (muestra):"] + resumir_lineas(salida_puertos, 14))
        if re.search(r"\b3389\b|\b445\b|\b139\b|\b5985\b|\b5986\b|\b22\b", salida_puertos):
            hallazgos.append("[MEDIO] Existen reglas inbound habilitadas sobre puertos sensibles")

    script_aplicaciones = (
        "$reglas = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
        "Get-NetFirewallApplicationFilter | Where-Object { $_.Program -and $_.Program -ne 'Any' }; "
        "$reglas | Select-Object -First 12 Program | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida_aplicaciones = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_aplicaciones], timeout=30)
    if salida_aplicaciones.strip():
        informacion.extend(["Aplicaciones permitidas por firewall inbound (muestra):"] + resumir_lineas(salida_aplicaciones, 14))
        if re.search(r"\\users\\|\\appdata\\|\\temp\\", salida_aplicaciones.lower()):
            hallazgos.append("[MEDIO] Hay reglas inbound asociadas a aplicaciones en rutas de usuario o temporales")

    if not informacion:
        informacion.append("No se obtuvo una muestra de exposición inbound por puerto o aplicación")

    return informacion, hallazgos


def obtener_software_seguridad_windows() -> tuple[list[str], list[str]]:
    """Inventaría productos de seguridad registrados y detecta posibles solapes de agentes."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar software de seguridad"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    comando_av = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,pathToSignedProductExe | Format-Table -Wrap -HideTableHeaders",
    ]
    _, salida_av = ejecutar_comando_seguro(comando_av, timeout=20)
    if salida_av.strip():
        informacion.extend(["Productos antivirus registrados:"] + resumir_lineas(salida_av, 10))

    comando_fw = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue | Select-Object displayName,pathToSignedProductExe | Format-Table -Wrap -HideTableHeaders",
    ]
    _, salida_fw = ejecutar_comando_seguro(comando_fw, timeout=20)
    if salida_fw.strip():
        informacion.extend(["Productos firewall registrados:"] + resumir_lineas(salida_fw, 10))

    texto = (salida_av + "\n" + salida_fw).strip()
    if texto:
        nombres = [linea.strip() for linea in texto.splitlines() if linea.strip() and '----' not in linea]
        if len(nombres) > 4:
            hallazgos.append("[INFO] Se detectan varios productos de seguridad registrados; revise compatibilidad y solapamientos")
    else:
        informacion.append("No se obtuvo inventario de productos de seguridad desde SecurityCenter2")

    return informacion, hallazgos


def obtener_perfiles_navegadores_windows() -> tuple[list[str], list[str]]:
    """Enumera perfiles locales de Chrome, Edge y Firefox presentes en el usuario actual."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar perfiles de navegadores"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$perfiles = @(); "
        "$rutaChrome = Join-Path $env:LOCALAPPDATA 'Google\\Chrome\\User Data'; "
        "if (Test-Path $rutaChrome) { "
        "  Get-ChildItem $rutaChrome -Directory -ErrorAction SilentlyContinue | "
        "  Where-Object { $_.Name -match '^(Default|Profile \\d+)$' } | "
        "  ForEach-Object { [PSCustomObject]@{ Navegador='Chrome'; Perfil=$_.Name; Ruta=$_.FullName } } "
        "} "
        "$rutaEdge = Join-Path $env:LOCALAPPDATA 'Microsoft\\Edge\\User Data'; "
        "if (Test-Path $rutaEdge) { "
        "  Get-ChildItem $rutaEdge -Directory -ErrorAction SilentlyContinue | "
        "  Where-Object { $_.Name -match '^(Default|Profile \\d+)$' } | "
        "  ForEach-Object { [PSCustomObject]@{ Navegador='Edge'; Perfil=$_.Name; Ruta=$_.FullName } } "
        "} "
        "$rutaFirefox = Join-Path $env:APPDATA 'Mozilla\\Firefox\\Profiles'; "
        "if (Test-Path $rutaFirefox) { "
        "  Get-ChildItem $rutaFirefox -Directory -ErrorAction SilentlyContinue | "
        "  ForEach-Object { [PSCustomObject]@{ Navegador='Firefox'; Perfil=$_.Name; Ruta=$_.FullName } } "
        "}"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script + " | Select-Object -First 18 Navegador,Perfil,Ruta | Format-Table -Wrap -HideTableHeaders"], timeout=35)

    if salida.strip():
        informacion.extend(["Perfiles de navegadores detectados (muestra):"] + resumir_lineas(salida, 20))
        total_perfiles = len([linea for linea in salida.splitlines() if linea.strip()])
        if total_perfiles > 8:
            hallazgos.append("[INFO] Se detectó un número elevado de perfiles de navegador; revise su necesidad")
    else:
        informacion.append("No se detectaron perfiles locales de Chrome, Edge o Firefox")

    return informacion, hallazgos


def obtener_extensiones_navegadores_windows() -> tuple[list[str], list[str]]:
    """Obtiene una muestra de extensiones instaladas en Chrome, Edge y Firefox."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar extensiones de navegadores"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$resultado = @(); "
        "$bases = @("
        "  @{ Navegador='Chrome'; Ruta=(Join-Path $env:LOCALAPPDATA 'Google\\Chrome\\User Data') },"
        "  @{ Navegador='Edge'; Ruta=(Join-Path $env:LOCALAPPDATA 'Microsoft\\Edge\\User Data') }"
        "); "
        "foreach ($base in $bases) { "
        "  if (Test-Path $base.Ruta) { "
        "    Get-ChildItem $base.Ruta -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \\d+)$' } | ForEach-Object { "
        "      $rutaExt = Join-Path $_.FullName 'Extensions'; "
        "      if (Test-Path $rutaExt) { "
        "        Get-ChildItem $rutaExt -Directory -ErrorAction SilentlyContinue | Select-Object -First 4 | ForEach-Object { "
        "          $dirVersion = Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1; "
        "          $nombre = $_.Name; "
        "          if ($dirVersion) { "
        "            $manifest = Join-Path $dirVersion.FullName 'manifest.json'; "
        "            if (Test-Path $manifest) { "
        "              try { $json = Get-Content $manifest -Raw -ErrorAction Stop | ConvertFrom-Json; if ($json.name) { $nombre = $json.name } } catch { } "
        "            } "
        "          } "
        "          $resultado += [PSCustomObject]@{ Navegador=$base.Navegador; Perfil=$_.PSParentPath.Split('::')[-1].Split('\\')[-2]; Extension=$nombre } "
        "        } "
        "      } "
        "    } "
        "  } "
        "} "
        "$rutaFirefox = Join-Path $env:APPDATA 'Mozilla\\Firefox\\Profiles'; "
        "if (Test-Path $rutaFirefox) { "
        "  Get-ChildItem $rutaFirefox -Directory -ErrorAction SilentlyContinue | Select-Object -First 4 | ForEach-Object { "
        "    $rutaJson = Join-Path $_.FullName 'extensions.json'; "
        "    if (Test-Path $rutaJson) { "
        "      try { "
        "        $datos = Get-Content $rutaJson -Raw -ErrorAction Stop | ConvertFrom-Json; "
        "        foreach ($addon in ($datos.addons | Select-Object -First 6)) { "
        "          $resultado += [PSCustomObject]@{ Navegador='Firefox'; Perfil=$_.Name; Extension=$addon.defaultLocale.name } "
        "        } "
        "      } catch { } "
        "    } "
        "  } "
        "} "
        "$resultado | Select-Object -First 24 Navegador,Perfil,Extension | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=45)

    if salida.strip():
        informacion.extend(["Extensiones de navegadores detectadas (muestra):"] + resumir_lineas(salida, 24))
        salida_minuscula = salida.lower()
        if re.search(r"remote|rdp|vnc|anydesk|teamviewer|rustdesk|ssh|sftp|wallet|crypto", salida_minuscula):
            hallazgos.append("[INFO] Se detectaron extensiones de navegador potencialmente sensibles; conviene revisarlas")
    else:
        informacion.append("No se obtuvo una muestra de extensiones instaladas en los navegadores revisados")

    return informacion, hallazgos


def obtener_certificados_cliente_navegadores_windows() -> tuple[list[str], list[str]]:
    """Busca certificados de autenticación de cliente en los almacenes usados por Edge y Chrome."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar certificados cliente de navegadores"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$eku = '1.3.6.1.5.5.7.3.2'; "
        "$resultado = @(); "
        "$almacenes = @('Cert:\\CurrentUser\\My','Cert:\\LocalMachine\\My'); "
        "foreach ($almacen in $almacenes) { "
        "  Get-ChildItem $almacen -ErrorAction SilentlyContinue | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains $eku } | ForEach-Object { "
        "    $resultado += [PSCustomObject]@{ Almacen=$almacen; Subject=$_.Subject; Issuer=$_.Issuer; NotAfter=$_.NotAfter } "
        "  } "
        "}; "
        "Write-Output ('Total certificados cliente: ' + ($resultado | Measure-Object).Count); "
        "Write-Output ('Expirados: ' + (($resultado | Where-Object { $_.NotAfter -lt (Get-Date) }) | Measure-Object).Count); "
        "Write-Output ('Próximos a caducar (<30 días): ' + (($resultado | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }) | Measure-Object).Count); "
        "$resultado | Select-Object -First 12 Almacen, Subject, NotAfter | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=35)

    if salida.strip():
        informacion.extend([
            "Certificados cliente para navegadores basados en almacén Windows:",
            "Nota: Edge y Chrome usan habitualmente el almacén del sistema; Firefox puede gestionar certificados propios.",
        ] + resumir_lineas(salida, 18))
        coincidencia_expirados = re.search(r"expirados:\s*(\d+)", salida.lower())
        coincidencia_proximos = re.search(r"próximos a caducar \(<30 días\):\s*(\d+)", salida.lower())
        if coincidencia_expirados and int(coincidencia_expirados.group(1)) > 0:
            hallazgos.append(f"[MEDIO] Se detectaron {coincidencia_expirados.group(1)} certificados cliente expirados")
        if coincidencia_proximos and int(coincidencia_proximos.group(1)) > 0:
            hallazgos.append(f"[MEDIO] Se detectaron {coincidencia_proximos.group(1)} certificados cliente próximos a caducar")
    else:
        informacion.append("No se detectaron certificados cliente en los almacenes revisados")

    return informacion, hallazgos


def obtener_certificados_firefox_windows() -> tuple[list[str], list[str]]:
    """Profundiza en certificados propios de Firefox revisando perfiles NSS, módulos PKCS#11 y excepciones TLS."""
    if not shutil.which("powershell"):
        return ["PowerShell no está disponible para consultar certificados propios de Firefox"], []

    informacion: list[str] = []
    hallazgos: list[str] = []

    script = (
        "$rutaFirefox = Join-Path $env:APPDATA 'Mozilla\\Firefox'; "
        "if (-not (Test-Path $rutaFirefox)) { return } "
        "$perfiles = Get-ChildItem (Join-Path $rutaFirefox 'Profiles') -Directory -ErrorAction SilentlyContinue; "
        "foreach ($perfil in ($perfiles | Select-Object -First 6)) { "
        "  $cert9 = Join-Path $perfil.FullName 'cert9.db'; "
        "  $key4 = Join-Path $perfil.FullName 'key4.db'; "
        "  $pkcs11 = Join-Path $perfil.FullName 'pkcs11.txt'; "
        "  $override = Join-Path $perfil.FullName 'cert_override.txt'; "
        "  $prefs = Join-Path $perfil.FullName 'prefs.js'; "
        "  $tieneCert9 = Test-Path $cert9; "
        "  $tieneKey4 = Test-Path $key4; "
        "  $tienePkcs11 = Test-Path $pkcs11; "
        "  $tieneOverride = Test-Path $override; "
        "  $enterpriseRoots = 'No determinado'; "
        "  $osClientCerts = 'No determinado'; "
        "  if (Test-Path $prefs) { "
        "    $contenido = Get-Content $prefs -Raw -ErrorAction SilentlyContinue; "
        "    if ($contenido -match 'security\\.enterprise_roots\\.enabled\",\\s*true') { $enterpriseRoots = 'true' } "
        "    elseif ($contenido -match 'security\\.enterprise_roots\\.enabled\",\\s*false') { $enterpriseRoots = 'false' } "
        "    if ($contenido -match 'security\\.osclientcerts\\.autoload\",\\s*true') { $osClientCerts = 'true' } "
        "    elseif ($contenido -match 'security\\.osclientcerts\\.autoload\",\\s*false') { $osClientCerts = 'false' } "
        "  } "
        "  [PSCustomObject]@{ Perfil=$perfil.Name; Cert9=$tieneCert9; Key4=$tieneKey4; PKCS11=$tienePkcs11; Overrides=$tieneOverride; EnterpriseRoots=$enterpriseRoots; OSClientCerts=$osClientCerts } "
        "} | Format-Table -Wrap -HideTableHeaders"
    )
    _, salida = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script], timeout=35)

    if salida.strip():
        informacion.extend([
            "Perfiles y almacenes NSS de Firefox (muestra):",
        ] + resumir_lineas(salida, 18))
        salida_minuscula = salida.lower()
        if "true" in salida_minuscula and "overrides" in salida_minuscula:
            hallazgos.append("[INFO] Algún perfil de Firefox contiene excepciones TLS/certificados almacenadas en cert_override.txt")
        if "enterpriseroots" in salida_minuscula and "false" in salida_minuscula:
            hallazgos.append("[INFO] Algún perfil de Firefox no parece confiar en raíces empresariales del sistema")
        if "osclientcerts" in salida_minuscula and "true" in salida_minuscula:
            hallazgos.append("[INFO] Firefox parece cargar certificados cliente del sistema en algún perfil")
    else:
        informacion.append("No se detectaron perfiles Firefox con información de certificados propia")

    script_pkcs11 = (
        "$rutaPerfiles = Join-Path (Join-Path $env:APPDATA 'Mozilla\\Firefox') 'Profiles'; "
        "if (Test-Path $rutaPerfiles) { "
        "  Get-ChildItem $rutaPerfiles -Directory -ErrorAction SilentlyContinue | Select-Object -First 4 | ForEach-Object { "
        "    $pkcs11 = Join-Path $_.FullName 'pkcs11.txt'; "
        "    if (Test-Path $pkcs11) { "
        "      Get-Content $pkcs11 -ErrorAction SilentlyContinue | Select-String -Pattern 'library=|name=|slot=' -CaseSensitive:$false | Select-Object -First 8 | ForEach-Object { $_.Line } "
        "    } "
        "  } "
        "}"
    )
    _, salida_pkcs11 = ejecutar_comando_seguro(["powershell", "-NoProfile", "-Command", script_pkcs11], timeout=25)
    if salida_pkcs11.strip():
        informacion.extend(["Módulos PKCS#11 de Firefox (muestra):"] + resumir_lineas(salida_pkcs11, 12))
        hallazgos.append("[INFO] Se detectaron módulos PKCS#11 en Firefox; podrían existir tokens o middleware criptográfico en uso")

    ruta_certutil = shutil.which("certutil")
    if ruta_certutil:
        ruta_perfiles = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
        if ruta_perfiles.exists():
            perfiles = [ruta for ruta in ruta_perfiles.iterdir() if ruta.is_dir()][:3]
            for perfil in perfiles:
                if not (perfil / "cert9.db").exists():
                    continue
                codigo, salida_certutil = ejecutar_comando_seguro(
                    [ruta_certutil, "-L", "-d", f"sql:{perfil}"],
                    timeout=20,
                )
                if codigo is not None and salida_certutil.strip():
                    informacion.extend([
                        f"Certificados NSS de Firefox en el perfil {perfil.name} (muestra):",
                    ] + resumir_lineas(salida_certutil, 14))
                    texto_certutil = salida_certutil.lower()
                    if re.search(r"client|usuario|autentic", texto_certutil):
                        hallazgos.append(f"[INFO] El perfil Firefox '{perfil.name}' contiene certificados con posible uso de autenticación")
                break

    return informacion, hallazgos


def obtener_controles_windows_avanzados() -> tuple[list[str], list[str]]:
    """Agrupa comprobaciones adicionales específicas de Windows para enriquecer la auditoría local."""
    informacion: list[str] = []
    hallazgos: list[str] = []

    for funcion in [
        obtener_bitlocker_windows,
        obtener_cuentas_locales_windows,
        obtener_controles_remotos_windows,
        obtener_windows_update_y_reinicio,
        obtener_defender_avanzado_windows,
        obtener_firma_smb_windows,
        obtener_politicas_auditoria_windows,
        obtener_laps_windows,
        obtener_logging_powershell_windows,
        obtener_firewall_perfiles_windows,
        obtener_eventos_criticos_windows,
        obtener_lsa_y_credential_guard_windows,
        obtener_applocker_y_wdac_windows,
        obtener_reglas_firewall_entrada_windows,
        obtener_smartscreen_windows,
        obtener_politica_powershell_windows,
        obtener_sesiones_recientes_windows,
        obtener_reglas_firewall_peligrosas_windows,
        obtener_proteccion_ransomware_defender_windows,
        obtener_remote_assistance_windows,
        obtener_servicios_automaticos_inusuales_windows,
        obtener_software_potencialmente_obsoleto_windows,
        obtener_autologon_windows,
        obtener_always_install_elevated_windows,
        obtener_autenticacion_legacy_windows,
        obtener_protocolos_tls_windows,
        obtener_persistencia_inicio_windows,
        obtener_proxy_y_dns_windows,
        obtener_certificados_windows,
        obtener_software_acceso_remoto_windows,
        obtener_tareas_sospechosas_windows,
        obtener_politicas_navegador_windows,
        obtener_permisos_smb_windows,
        obtener_eventos_altas_privilegios_windows,
        obtener_dispositivos_usb_windows,
        obtener_perfiles_wifi_windows,
        obtener_historial_rdp_windows,
        obtener_persistencia_winlogon_lsa_windows,
        obtener_path_y_entorno_windows,
        obtener_exposicion_firewall_windows,
        obtener_software_seguridad_windows,
        obtener_perfiles_navegadores_windows,
        obtener_extensiones_navegadores_windows,
        obtener_certificados_cliente_navegadores_windows,
        obtener_certificados_firefox_windows,
    ]:
        informacion_parcial, hallazgos_parciales = funcion()
        informacion.extend(informacion_parcial)
        hallazgos.extend(hallazgos_parciales)

    return informacion, hallazgos