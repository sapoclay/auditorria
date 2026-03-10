from pathlib import Path

# Nombre visible de la aplicación en consola, ventanas y PDF.
NOMBRE_APLICACION = "AudiTorría"

# Puertos habituales que se revisarán por defecto si el usuario no define otros.
PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternativo",
    8443: "HTTPS Alternativo",
}

# Límite de hosts para evitar que una red enorme bloquee la interfaz durante mucho tiempo.
MAXIMO_HOSTS_RED = 1024

# Carpeta base para almacenar los informes PDF generados.
CARPETA_REPORTES = Path("reportes")

# Configuración de consulta de vulnerabilidades CVE para servicios detectados.
URL_API_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAXIMO_CVES_POR_SERVICIO = 5
TIEMPO_ESPERA_API_CVES = 10
