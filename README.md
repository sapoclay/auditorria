# AudiTorría

<img width="1408" height="768" alt="logo" src="https://github.com/user-attachments/assets/a401e6bf-af56-4f23-9b76-0d93ebff2f3a" />

AudiTorría es una herramienta creada para revisar la seguridad básica de equipos y redes.
Funciona en Linux y Windows, tiene interfaz gráfica y permite guardar los resultados en PDF.

## Qué puede hacer

- revisar una red completa
- revisar direcciones IP concretas
- revisar el propio ordenador en el que se ejecuta
- mostrar los resultados en pantalla
- guardar los resultados en un PDF
- buscar fallos de seguridad conocidos cuando consigue averiguar la versión de un programa

## ¿Qué revisa este programa?

### Por red

AudiTorría puede:

- comprobar qué equipos responden
- ver qué puertos están abiertos
- intentar averiguar qué servicio hay detrás de cada puerto
- leer la información visible que algunos servicios muestran al conectarse
- intentar adivinar la versión de algunos programas expuestos
- buscar si esa versión aparece relacionada con fallos de seguridad conocidos

### En el equipo local

AudiTorría puede revisar, entre otras cosas:

- puertos abiertos en el propio equipo
- cortafuegos
- actualizaciones
- usuarios y permisos
- tareas automáticas
- recursos compartidos
- programas importantes instalados
- versiones reales de algunos servicios
- posible relación entre esas versiones y fallos de seguridad conocidos

### En Windows

Incluye muchas comprobaciones a mayores, como por ejemplo:

- protección general del sistema
- acceso remoto
- cuentas con permisos altos
- programas que se inician solos
- reglas del cortafuegos
- dispositivos USB
- redes Wi‑Fi guardadas
- programas de acceso remoto
- navegadores, extensiones y certificados

## Qué significa “detectar versiones por red”

Cuando AudiTorría se conecta a un servicio, a veces ese servicio devuelve una pequeña respuesta visible.
Esa respuesta puede indicar qué programa está funcionando y qué versión parece tener.

Con esa pista, AudiTorría intenta buscar si esa versión aparece asociada a fallos de seguridad publicados.

## Qué significa “buscar CVEs”

Cuando el programa consigue obtener un nombre y una versión, intenta compararlos con una base pública de fallos de seguridad conocidos.

Eso sirve para:

- señalar posibles problemas
- dar prioridad a los más graves
- incluir esa información en la pantalla y en el PDF

## Interfaz gráfica

La interfaz incluye:

- tabla de resultados
- filtros de búsqueda
- detalle completo por equipo
- colores para distinguir mejor el riesgo
- documentación integrada por pestañas
- buscador dentro de la documentación

## Informes PDF

Los informes pueden incluir:

- resumen general
- detalle de cada equipo
- puertos abiertos
- información adicional del sistema
- avisos importantes
- versiones detectadas
- fallos de seguridad conocidos relacionados

En la auditoría local, el PDF muestra las direcciones IP detectadas en el propio equipo.

## Archivos principales del proyecto

- [run_app.py](run_app.py): arranque del programa
- [audittorria_main.py](audittorria_main.py): punto de entrada
- [audittorria/](audittorria/): código principal
- [docs/documentacion_controles.md](docs/documentacion_controles.md): documentación completa
- [img/](img/): imágenes del proyecto
- [reportes/](reportes/): informes generados

## Requisitos

- Python 3.10 o superior recomendado
- Linux o Windows
- conexión a Internet si se quiere buscar información pública sobre fallos de seguridad conocidos

## Instalación

Clona el repositorio y ejecuta:

- `python3 run_app.py` en Linux
- `python run_app.py` en Windows

El lanzador crea el entorno de trabajo si hace falta, instala lo necesario y abre la aplicación.

## Uso rápido

### Abrir la interfaz gráfica

- `python3 run_app.py`

### Usar por consola

- revisar una red:
  - `python3 run_app.py --modo consola --red 192.168.1.0/24`
  - también puede escribir `192.168.1.0` y el programa lo interpretará como `192.168.1.0/24`
- revisar IPs concretas:
  - `python3 run_app.py --modo consola --ips 192.168.1.10,192.168.1.20`
- revisar el equipo local:
  - `python3 run_app.py --modo consola --local`

## Limitaciones

- no todos los servicios muestran información suficiente
- algunas versiones solo pueden adivinarse, no confirmarse
- no todos los fallos de seguridad conocidos aplican necesariamente al equipo real
- algunas comprobaciones dependen del sistema operativo y de los permisos disponibles
- la herramienta ayuda mucho, pero no sustituye una auditoría completa hecha por un profesional

## Uso responsable

Usa AudiTorría solo debería utilizarse sobre equipos propios o con permiso expreso del dueño.

## Repositorio

Proyecto: [https://github.com/sapoclay/auditorria](https://github.com/sapoclay/auditorria)

Creado por entreunosyceros
