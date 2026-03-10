from __future__ import annotations

import sys

from audittorria import ejecutar_aplicacion


# Este archivo sirve como punto de entrada ligero para el lanzador `run_app.py`.
if __name__ == "__main__":
    sys.exit(ejecutar_aplicacion(sys.argv[1:]))
