import os
import sys
import platform
import subprocess
import venv
from pathlib import Path
import hashlib

# Configuración principal del lanzador.
VENV_DIR = '.venv'
MAIN_FILE = 'audittorria_main.py'
REQUIREMENTS_FILE = 'requirements.txt'


def is_venv_exists():
    """Comprueba si el entorno virtual existe y es válido"""
    if not os.path.exists(VENV_DIR) or not os.path.isdir(VENV_DIR):
        return False
    
    # Verificar que el ejecutable Python existe dentro del venv
    python_exe = get_python_executable()
    if not os.path.exists(python_exe):
        return False
    
    return True


def create_venv():
    """Crea el entorno virtual"""
    # Si existe un directorio .venv corrupto, eliminarlo primero
    if os.path.exists(VENV_DIR):
        print("Eliminando entorno virtual corrupto...")
        import shutil
        shutil.rmtree(VENV_DIR)
    
    print("Creando el entorno virtual...")
    venv.create(VENV_DIR, with_pip=True)

    # Actualizar pip, setuptools y wheel
    pip_exe = get_pip_executable()
    subprocess.run([pip_exe, 'install', '--upgrade', 'pip', 'setuptools', 'wheel'], 
                   check=True, capture_output=True)
    print(f" [OK] Entorno virtual creado en: {VENV_DIR}")


def get_python_executable():
    """Obtiene la ruta al ejecutable Python del entorno virtual"""
    if platform.system().lower() == 'windows':
        return os.path.join(VENV_DIR, 'Scripts', 'python.exe')
    return os.path.join(VENV_DIR, 'bin', 'python')


def get_pip_executable():
    """Obtiene la ruta al ejecutable pip del entorno virtual"""
    if platform.system().lower() == 'windows':
        return os.path.join(VENV_DIR, 'Scripts', 'pip.exe')
    return os.path.join(VENV_DIR, 'bin', 'pip')

def install_requirements():
    """Instala las dependencias desde requirements.txt"""
    pip_exe = get_pip_executable()

    if not os.path.exists(REQUIREMENTS_FILE):
        print(f"[OK]  {REQUIREMENTS_FILE} no encontrado, continuando sin dependencias extras...")
        return

    # Evitar reinstalaciones innecesarias si requirements.txt no cambió
    req_path = Path(REQUIREMENTS_FILE)
    stamp_path = Path(VENV_DIR) / '.requirements.sha256'
    req_hash = hashlib.sha256(req_path.read_bytes()).hexdigest()
    
    if stamp_path.exists() and stamp_path.read_text(encoding='utf-8').strip() == req_hash:
        print("[OK] Dependencias verificadas (sin cambios)")
        return

    print("Instalando dependencias...")
    subprocess.run([pip_exe, 'install', '-r', REQUIREMENTS_FILE], check=True)
    stamp_path.write_text(req_hash, encoding='utf-8')
    print("   [OK] Dependencias instaladas")


def run_main_app(args=None):
    """Ejecuta la aplicación principal después de configurar el entorno virtual"""
    python_exe = get_python_executable()
	
    if not os.path.exists(MAIN_FILE):
        print(f"[!] Error: {MAIN_FILE} no encontrado")
        sys.exit(1)
	
    print(f"[OK] Iniciando AudiTorría...\n")
    print("─" * 70)
    args = args or []
    subprocess.run([python_exe, MAIN_FILE, *args], check=True)


def print_banner():
    """Muestra el banner del lanzador"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                               AudiTorría                                      ║
║                  Lanzador de auditoría de red y seguridad                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝
""")


def main():
    """Función principal del lanzador"""
    # Cambiar al directorio que contenga este script
    os.chdir(Path(__file__).parent)
    
    print_banner()

    try:
        # Paso 1: Verificar/crear entorno virtual
        if is_venv_exists():
            print(f"[OK] Entorno virtual encontrado: {VENV_DIR}")
        else:
            print(f"[OK]  Entorno virtual no encontrado")
            create_venv()
        
        # Paso 2: Instalar dependencias
        install_requirements()
        
        # Paso 3: Ejecutar aplicación (reenviando argumentos)
        run_main_app(sys.argv[1:])
        
    except KeyboardInterrupt:
        print("\n[OK] AudiTorría finalizado por el usuario")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        # Ignorar si el proceso fue interrumpido por señal (código 130 = SIGINT)
        if e.returncode == 130 or e.returncode == -2:
            print("\n[OK] AudiTorría finalizado correctamente")
            sys.exit(0)
        print(f"[!] Error ocurrido: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
    