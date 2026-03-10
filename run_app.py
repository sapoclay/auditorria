import os
import sys
import platform
import subprocess
import venv
from pathlib import Path
import hashlib

# Configuración principal del lanzador.
DIRECTORIO_ENTORNO_VIRTUAL = '.venv'
ARCHIVO_PRINCIPAL = 'audittorria_main.py'
ARCHIVO_REQUISITOS = 'requirements.txt'
ALIASES_MODO_GRAFICO = {'--gui', '--grafico'}
ALIASES_MODO_CONSOLA = {'--cli', '--consola'}


def existe_entorno_virtual():
    """Comprueba si el entorno virtual existe y es válido"""
    if not os.path.exists(DIRECTORIO_ENTORNO_VIRTUAL) or not os.path.isdir(DIRECTORIO_ENTORNO_VIRTUAL):
        return False
    
    # Verificar que el ejecutable Python existe dentro del venv
    ejecutable_python = obtener_ejecutable_python()
    if not os.path.exists(ejecutable_python):
        return False
    
    return True


def crear_entorno_virtual():
    """Crea el entorno virtual"""
    # Si existe un directorio .venv corrupto, eliminarlo primero
    if os.path.exists(DIRECTORIO_ENTORNO_VIRTUAL):
        print("Eliminando entorno virtual corrupto...")
        import shutil
        shutil.rmtree(DIRECTORIO_ENTORNO_VIRTUAL)
    
    print("Creando el entorno virtual...")
    venv.create(DIRECTORIO_ENTORNO_VIRTUAL, with_pip=True)

    # Actualizar pip, setuptools y wheel. En Windows es más fiable usar
    # `python -m pip` que invocar `pip.exe` directamente.
    print("Actualizando herramientas base del entorno...")
    try:
        ejecutar_comando_pip('install', '--upgrade', 'pip', 'setuptools', 'wheel', capture_output=True)
    except subprocess.CalledProcessError as error_subproceso:
        print("[!] No se pudieron actualizar pip/setuptools/wheel.")
        print("    Se continuará con las versiones incluidas en el entorno virtual.")
        detalles = formatear_error_subproceso(error_subproceso)
        if detalles:
            print(detalles)
    print(f" [OK] Entorno virtual creado en: {DIRECTORIO_ENTORNO_VIRTUAL}")


def obtener_ejecutable_python():
    """Obtiene la ruta al ejecutable Python del entorno virtual"""
    if platform.system().lower() == 'windows':
        return os.path.join(DIRECTORIO_ENTORNO_VIRTUAL, 'Scripts', 'python.exe')
    return os.path.join(DIRECTORIO_ENTORNO_VIRTUAL, 'bin', 'python')


def ejecutar_comando_pip(*argumentos, capture_output=False):
    """Ejecuta pip usando `python -m pip` para evitar problemas con `pip.exe`"""
    ejecutable_python = obtener_ejecutable_python()
    return subprocess.run(
        [ejecutable_python, '-m', 'pip', *argumentos],
        check=True,
        capture_output=capture_output,
        text=capture_output,
    )


def formatear_error_subproceso(error_subproceso):
    """Devuelve una versión legible del stderr/stdout de un subproceso fallido"""
    partes = []
    salida_estandar = getattr(error_subproceso, 'stdout', None)
    salida_error = getattr(error_subproceso, 'stderr', None)

    if salida_estandar:
        partes.append(salida_estandar.strip())
    if salida_error:
        partes.append(salida_error.strip())

    return "\n".join(parte for parte in partes if parte)


def normalizar_argumentos_lanzador(argumentos=None):
    """Normaliza alias del lanzador para que ambos modos sean fáciles de invocar."""
    argumentos_normalizados = []

    for argumento in argumentos or []:
        argumento_normalizado = argumento.lower()
        if argumento_normalizado in ALIASES_MODO_GRAFICO:
            argumentos_normalizados.extend(['--modo', 'grafico'])
            continue
        if argumento_normalizado in ALIASES_MODO_CONSOLA:
            argumentos_normalizados.extend(['--modo', 'consola'])
            continue
        argumentos_normalizados.append(argumento)

    return argumentos_normalizados


def instalar_requisitos():
    """Instala las dependencias desde requirements.txt"""
    if not os.path.exists(ARCHIVO_REQUISITOS):
        print(f"[OK]  {ARCHIVO_REQUISITOS} no encontrado, continuando sin dependencias extras...")
        return

    # Evitar reinstalaciones innecesarias si requirements.txt no cambió
    ruta_requisitos = Path(ARCHIVO_REQUISITOS)
    ruta_marca = Path(DIRECTORIO_ENTORNO_VIRTUAL) / '.requirements.sha256'
    hash_requisitos = hashlib.sha256(ruta_requisitos.read_bytes()).hexdigest()
    
    if ruta_marca.exists() and ruta_marca.read_text(encoding='utf-8').strip() == hash_requisitos:
        print("[OK] Dependencias verificadas (sin cambios)")
        return

    print("Instalando dependencias...")
    ejecutar_comando_pip('install', '-r', ARCHIVO_REQUISITOS)
    ruta_marca.write_text(hash_requisitos, encoding='utf-8')
    print("   [OK] Dependencias instaladas")


def asegurar_entorno():
    """Verifica el entorno virtual y las dependencias necesarias antes del arranque."""
    if existe_entorno_virtual():
        print(f"[OK] Entorno virtual encontrado: {DIRECTORIO_ENTORNO_VIRTUAL}")
    else:
        print(f"[OK]  Entorno virtual no encontrado")
        crear_entorno_virtual()

    instalar_requisitos()


def ejecutar_aplicacion_principal(argumentos=None):
    """Ejecuta la aplicación principal después de configurar el entorno virtual"""
    argumentos = normalizar_argumentos_lanzador(argumentos)
    ejecutable_python = obtener_ejecutable_python()

    if not os.path.exists(ARCHIVO_PRINCIPAL):
        print(f"[!] Error: {ARCHIVO_PRINCIPAL} no encontrado")
        sys.exit(1)

    print(f"[OK] Iniciando AudiTorría...\n")
    print("─" * 70)
    subprocess.run([ejecutable_python, ARCHIVO_PRINCIPAL, *argumentos], check=True)


def mostrar_banner():
    """Muestra el banner del lanzador"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                               AudiTorría                                      ║
║                  Lanzador de auditoría de red y seguridad                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝
""")


def principal(argumentos=None):
    """Función principal del lanzador"""
    # Cambiar al directorio que contenga este script
    os.chdir(Path(__file__).parent)
    
    mostrar_banner()

    try:
        asegurar_entorno()
        ejecutar_aplicacion_principal(argumentos if argumentos is not None else sys.argv[1:])
        
    except KeyboardInterrupt:
        print("\n[OK] AudiTorría finalizado por el usuario")
        sys.exit(0)
    except subprocess.CalledProcessError as error_subproceso:
        # Ignorar si el proceso fue interrumpido por señal (código 130 = SIGINT)
        if error_subproceso.returncode == 130 or error_subproceso.returncode == -2:
            print("\n[OK] AudiTorría finalizado correctamente")
            sys.exit(0)
        print(f"[!] Error ocurrido: {error_subproceso}")
        detalles = formatear_error_subproceso(error_subproceso)
        if detalles:
            print(detalles)
        sys.exit(1)
    except Exception as error_inesperado:
        print(f"[!] Error inesperado: {error_inesperado}")
        sys.exit(1)


if __name__ == '__main__':
    principal()
    