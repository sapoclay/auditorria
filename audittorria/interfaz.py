"""Implementa la interfaz gráfica de AudiTorría con Tkinter.

Gestiona la ventana principal, la recogida de parámetros, el lanzamiento de la
auditoría en segundo plano y la visualización de resultados, filtros y ayudas
desde una capa puramente visual.
"""

from __future__ import annotations

import os
import queue
import threading
import traceback
import webbrowser
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import cast

from PIL import Image, ImageTk

from .configuracion import NOMBRE_APLICACION
from .modelos import ParametrosAuditoria, ProgresoAuditoria, ResultadoEquipo, ResumenAuditoria
from .servicio import ejecutar_auditoria_completa
from .utilidades import (
    construir_ruta_pdf,
    normalizar_red_para_auditoria,
    obtener_objetivos_desde_ips,
    obtener_objetivos_desde_red,
    obtener_puertos,
)


# --------------------------------------------------------------------------------------
# Interfaz gráfica construida con Tkinter para mantener compatibilidad con Linux y Windows.
# --------------------------------------------------------------------------------------


class VentanaPrincipal:
    """Gestiona los controles visuales y el flujo de trabajo de la interfaz gráfica."""

    def __init__(self) -> None:
        # Se crea la ventana principal y se inicializan las variables de estado.
        self.raiz = tk.Tk()
        self.raiz.title(NOMBRE_APLICACION)
        self.raiz.geometry("980x720")
        self.raiz.minsize(900, 650)
        self.raiz.configure(bg="#F2F5F7")

        self.cola_mensajes: queue.Queue[tuple[str, object]] = queue.Queue()
        self.hilo_auditoria: threading.Thread | None = None

        # Variables enlazadas a los controles para simplificar lectura y escritura de datos.
        self.modo_objetivo_var = tk.StringVar(value="red")
        self.red_var = tk.StringVar()
        self.ips_var = tk.StringVar()
        self.puertos_var = tk.StringVar(value="21,22,23,25,53,80,110,135,139,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443")
        self.salida_var = tk.StringVar(value=str(construir_ruta_pdf(None)))
        self.concurrencia_var = tk.StringVar(value="32")
        self.estado_var = tk.StringVar(value="Todo listo para empezar la revisión.")
        self.porcentaje_var = tk.StringVar(value="0%")
        self.filtro_texto_var = tk.StringVar()
        self.filtro_estado_var = tk.StringVar(value="Todos")
        self.filtro_solo_puertos_var = tk.BooleanVar(value=False)

        # Estas estructuras mantienen los resultados en memoria para filtrarlos y ver detalles.
        self.resultados_actuales: list[ResultadoEquipo] = []
        self.resultados_por_ip: dict[str, ResultadoEquipo] = {}
        self.imagen_logo_sobre: ImageTk.PhotoImage | None = None

        self._construir_interfaz()
        self._programar_revision_cola()

    def _construir_interfaz(self) -> None:
        """Crea la distribución visual de la ventana principal."""
        self._construir_menu_superior()

        marco_principal = ttk.Frame(self.raiz, padding=18)
        marco_principal.pack(fill=tk.BOTH, expand=True)

        # Se parte de la fuente por defecto del sistema para evitar errores de Tk
        # en plataformas donde el nombre de la fuente contiene espacios o no existe.
        fuente_base = tkfont.nametofont("TkDefaultFont")
        fuente_base.configure(size=10)
        fuente_titulo = tkfont.Font(
            family=fuente_base.actual("family"),
            size=18,
            weight="bold",
        )
        fuente_subtitulo = tkfont.Font(
            family=fuente_base.actual("family"),
            size=10,
        )

        estilo = ttk.Style()
        estilo.theme_use("clam")
        estilo.configure("TFrame", background="#F2F5F7")
        estilo.configure("TLabel", background="#F2F5F7")
        estilo.configure("TLabelframe", background="#F2F5F7")
        estilo.configure("TLabelframe.Label", background="#F2F5F7", foreground="#12344D")
        estilo.configure("TNotebook", background="#F2F5F7", borderwidth=0)
        estilo.configure("TNotebook.Tab", background="#E4E9ED", padding=(12, 6))
        estilo.map(
            "TNotebook.Tab",
            background=[("selected", "#F2F5F7")],
            foreground=[("selected", "#12344D")],
        )
        estilo.configure(".", font=fuente_base)
        estilo.configure("Titulo.TLabel", font=fuente_titulo, foreground="#12344D")
        estilo.configure("Subtitulo.TLabel", font=fuente_subtitulo, foreground="#476273")

        encabezado = ttk.Frame(marco_principal)
        encabezado.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(encabezado, text=NOMBRE_APLICACION, style="Titulo.TLabel").pack(anchor=tk.W)
        ttk.Label(
            encabezado,
            text="Revisión de equipos y redes con informe en PDF.",
            style="Subtitulo.TLabel",
        ).pack(anchor=tk.W)

        panel_configuracion = ttk.LabelFrame(marco_principal, text="Configuración de la auditoría", padding=14)
        panel_configuracion.pack(fill=tk.X)
        panel_configuracion.columnconfigure(1, weight=1)

        # Selector del tipo de objetivo a auditar.
        ttk.Label(panel_configuracion, text="Qué quiere revisar:").grid(row=0, column=0, sticky=tk.W, pady=4)
        marco_modo = ttk.Frame(panel_configuracion)
        marco_modo.grid(row=0, column=1, sticky=tk.W, pady=4)
        ttk.Radiobutton(
            marco_modo,
            text="Rango de red",
            value="red",
            variable=self.modo_objetivo_var,
            command=self._actualizar_estado_campos,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(
            marco_modo,
            text="Direcciones IP",
            value="ips",
            variable=self.modo_objetivo_var,
            command=self._actualizar_estado_campos,
        ).pack(side=tk.LEFT)
        ttk.Radiobutton(
            marco_modo,
            text="Equipo local",
            value="local",
            variable=self.modo_objetivo_var,
            command=self._actualizar_estado_campos,
        ).pack(side=tk.LEFT, padx=(12, 0))

        # Campo para red o IP base.
        ttk.Label(panel_configuracion, text="Red:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.entrada_red = ttk.Entry(panel_configuracion, textvariable=self.red_var)
        self.entrada_red.grid(row=1, column=1, sticky=tk.EW, pady=4)
        ttk.Label(panel_configuracion, text="Ejemplo: 192.168.1.0 o 192.168.1.0/24").grid(row=1, column=2, sticky=tk.W, padx=(12, 0))

        # Campo para lista de IPs manuales.
        ttk.Label(panel_configuracion, text="Direcciones IP:").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.entrada_ips = ttk.Entry(panel_configuracion, textvariable=self.ips_var)
        self.entrada_ips.grid(row=2, column=1, sticky=tk.EW, pady=4)
        ttk.Label(panel_configuracion, text="Separadas por comas").grid(row=2, column=2, sticky=tk.W, padx=(12, 0))

        # Campo para personalizar los puertos revisados.
        ttk.Label(panel_configuracion, text="Puertos a revisar:").grid(row=3, column=0, sticky=tk.W, pady=4)
        ttk.Entry(panel_configuracion, textvariable=self.puertos_var).grid(row=3, column=1, sticky=tk.EW, pady=4)
        ttk.Label(panel_configuracion, text="Ejemplo: 22,80,443,8000-8010").grid(row=3, column=2, sticky=tk.W, padx=(12, 0))

        # Campo de salida para el PDF.
        ttk.Label(panel_configuracion, text="Guardar informe en:").grid(row=4, column=0, sticky=tk.W, pady=4)
        ttk.Entry(panel_configuracion, textvariable=self.salida_var).grid(row=4, column=1, sticky=tk.EW, pady=4)
        ttk.Button(panel_configuracion, text="Examinar", command=self._seleccionar_pdf).grid(row=4, column=2, sticky=tk.W, padx=(12, 0))

        # Ajuste fino del número de hilos concurrentes.
        ttk.Label(panel_configuracion, text="Velocidad de revisión:").grid(row=5, column=0, sticky=tk.W, pady=4)
        ttk.Spinbox(panel_configuracion, from_=1, to=128, textvariable=self.concurrencia_var, width=8).grid(
            row=5,
            column=1,
            sticky=tk.W,
            pady=4,
        )

        marco_botones = ttk.Frame(marco_principal)
        marco_botones.pack(fill=tk.X, pady=12)
        self.boton_ejecutar = ttk.Button(marco_botones, text="Empezar revisión", command=self._iniciar_auditoria)
        self.boton_ejecutar.pack(side=tk.LEFT)
        ttk.Button(marco_botones, text="Limpiar mensajes", command=self._limpiar_registro).pack(side=tk.LEFT, padx=10)
        ttk.Button(marco_botones, text="Abrir carpeta de informes", command=self._abrir_carpeta_reportes).pack(side=tk.LEFT)

        # Barra de progreso determinista para mostrar el porcentaje real procesado.
        marco_progreso = ttk.Frame(marco_principal)
        marco_progreso.pack(fill=tk.X, pady=(0, 10))
        self.barra_progreso = ttk.Progressbar(marco_progreso, mode="determinate", maximum=100)
        self.barra_progreso.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(marco_progreso, textvariable=self.porcentaje_var, width=8).pack(side=tk.LEFT, padx=(10, 0))

        # Etiqueta de estado para mensajes breves y visibles.
        ttk.Label(marco_principal, textvariable=self.estado_var).pack(anchor=tk.W, pady=(0, 8))

        # Se usa un panel con pestañas para separar el log y la tabla de resultados.
        panel_inferior = ttk.Notebook(marco_principal)
        panel_inferior.pack(fill=tk.BOTH, expand=True)

        panel_resultados = ttk.Frame(panel_inferior, padding=10)
        panel_inferior.add(panel_resultados, text="Resultados")
        panel_resultados.rowconfigure(1, weight=1)
        panel_resultados.columnconfigure(0, weight=1)

        # Panel de filtros para reducir rápidamente los resultados mostrados en la tabla.
        marco_filtros = ttk.LabelFrame(panel_resultados, text="Filtros", padding=10)
        marco_filtros.grid(row=0, column=0, columnspan=2, sticky=tk.EW, pady=(0, 10))
        marco_filtros.columnconfigure(1, weight=1)

        ttk.Label(marco_filtros, text="Buscar:").grid(row=0, column=0, sticky=tk.W, pady=4)
        entrada_filtro_texto = ttk.Entry(marco_filtros, textvariable=self.filtro_texto_var)
        entrada_filtro_texto.grid(row=0, column=1, sticky=tk.EW, pady=4)
        entrada_filtro_texto.bind("<KeyRelease>", self._aplicar_filtros_tabla)

        ttk.Label(marco_filtros, text="Estado:").grid(row=0, column=2, sticky=tk.W, padx=(12, 0), pady=4)
        selector_estado = ttk.Combobox(
            marco_filtros,
            textvariable=self.filtro_estado_var,
            values=["Todos", "Activos", "Sin respuesta"],
            state="readonly",
            width=18,
        )
        selector_estado.grid(row=0, column=3, sticky=tk.W, pady=4)
        selector_estado.bind("<<ComboboxSelected>>", self._aplicar_filtros_tabla)

        ttk.Checkbutton(
            marco_filtros,
            text="Solo con puertos abiertos",
            variable=self.filtro_solo_puertos_var,
            command=self._aplicar_filtros_tabla,
        ).grid(row=0, column=4, sticky=tk.W, padx=(12, 0), pady=4)

        ttk.Button(marco_filtros, text="Limpiar filtros", command=self._limpiar_filtros).grid(
            row=0,
            column=5,
            sticky=tk.E,
            padx=(12, 0),
            pady=4,
        )

        columnas = ("ip", "estado", "riesgo", "host", "tiempo", "puertos", "ttl")
        self.tabla_resultados = ttk.Treeview(panel_resultados, columns=columnas, show="headings", height=12)
        self.tabla_resultados.heading("ip", text="IP")
        self.tabla_resultados.heading("estado", text="Estado")
        self.tabla_resultados.heading("riesgo", text="Riesgo")
        self.tabla_resultados.heading("host", text="Host")
        self.tabla_resultados.heading("tiempo", text="Ping")
        self.tabla_resultados.heading("puertos", text="Puertos abiertos")
        self.tabla_resultados.heading("ttl", text="TTL")
        self.tabla_resultados.column("ip", width=130, anchor=tk.W)
        self.tabla_resultados.column("estado", width=120, anchor=tk.W)
        self.tabla_resultados.column("riesgo", width=100, anchor=tk.CENTER)
        self.tabla_resultados.column("host", width=180, anchor=tk.W)
        self.tabla_resultados.column("tiempo", width=90, anchor=tk.W)
        self.tabla_resultados.column("puertos", width=230, anchor=tk.W)
        self.tabla_resultados.column("ttl", width=70, anchor=tk.CENTER)
        self.tabla_resultados.grid(row=1, column=0, sticky=tk.NSEW)
        self.tabla_resultados.bind("<Double-1>", self._mostrar_detalle_equipo)
        self._configurar_colores_tabla(self.tabla_resultados)

        barra_resultados = ttk.Scrollbar(panel_resultados, orient=tk.VERTICAL, command=self.tabla_resultados.yview)
        barra_resultados.grid(row=1, column=1, sticky=tk.NS)
        self.tabla_resultados.configure(yscrollcommand=barra_resultados.set)

        ttk.Label(
            panel_resultados,
            text="Consejo: haga doble clic sobre una fila para ver toda la información del equipo.",
        ).grid(row=2, column=0, sticky=tk.W, pady=(8, 0))

        panel_registro = ttk.Frame(panel_inferior, padding=10)
        panel_inferior.add(panel_registro, text="Registro")
        panel_registro.rowconfigure(0, weight=1)
        panel_registro.columnconfigure(0, weight=1)

        self.texto_registro = tk.Text(panel_registro, wrap="word", height=22, bg="#0F1720", fg="#D8E1E8")
        self.texto_registro.grid(row=0, column=0, sticky=tk.NSEW)
        barra_desplazamiento = ttk.Scrollbar(panel_registro, orient=tk.VERTICAL, command=self.texto_registro.yview)
        barra_desplazamiento.grid(row=0, column=1, sticky=tk.NS)
        self.texto_registro.configure(yscrollcommand=barra_desplazamiento.set)

        self._actualizar_estado_campos()
        self._escribir_registro("La ventana se abrió correctamente.")

    def _construir_menu_superior(self) -> None:
        """Crea el menú superior con el acceso a la leyenda de colores de la tabla."""
        menu_principal = tk.Menu(self.raiz)

        menu_archivo = tk.Menu(menu_principal, tearoff=False)
        menu_archivo.add_command(label="Salir", command=self.raiz.destroy)
        menu_principal.add_cascade(label="Archivo", menu=menu_archivo)

        menu_ayuda = tk.Menu(menu_principal, tearoff=False)
        menu_ayuda.add_command(label="Documentación", command=self._abrir_documentacion)
        menu_ayuda.add_command(label="Leyenda de colores", command=self._abrir_leyenda_colores)
        menu_ayuda.add_command(label="Sobre", command=self._abrir_ventana_sobre)
        menu_principal.add_cascade(label="Ayuda", menu=menu_ayuda)
        self.raiz.configure(menu=menu_principal)

    def _obtener_ruta_documentacion(self) -> Path:
        """Devuelve la ruta del archivo externo de documentación funcional."""
        return Path(__file__).resolve().parent.parent / "docs" / "documentacion_controles.md"

    def _obtener_documentacion_controles(self) -> str:
        """Carga la documentación funcional desde un archivo independiente."""
        ruta_documentacion = self._obtener_ruta_documentacion()
        try:
            return ruta_documentacion.read_text(encoding="utf-8")
        except OSError:
            return (
                f"# Documentación de controles de {NOMBRE_APLICACION}\n\n"
                "No se pudo leer el archivo de documentación externo.\n"
                f"Ruta esperada: {ruta_documentacion}"
            )

    def _separar_documentacion_en_pestanas(self, texto: str) -> list[tuple[str, str]]:
        """Divide la documentación en pestañas usando los encabezados markdown de segundo nivel."""
        titulo_actual = "General"
        lineas_actuales: list[str] = []
        secciones: list[tuple[str, str]] = []

        for linea in texto.splitlines():
            if linea.startswith("# "):
                continue
            if linea.startswith("## "):
                contenido_actual = "\n".join(lineas_actuales).strip()
                if contenido_actual:
                    secciones.append((titulo_actual, contenido_actual))
                titulo_actual = linea[3:].strip()
                lineas_actuales = []
                continue
            if linea.startswith("### "):
                lineas_actuales.append(linea[4:].strip().upper())
                continue

            if not lineas_actuales and not linea.strip():
                continue
            lineas_actuales.append(linea)

        contenido_actual = "\n".join(lineas_actuales).strip()
        if contenido_actual:
            secciones.append((titulo_actual, contenido_actual))

        return [(titulo, contenido if contenido else "Sin contenido") for titulo, contenido in secciones]

    def _abrir_documentacion(self) -> None:
        """Muestra una ventana con documentación por pestañas y búsqueda global sobre todas ellas."""
        ventana_documentacion = tk.Toplevel(self.raiz)
        ventana_documentacion.title("Ayuda - Documentación")
        ventana_documentacion.geometry("980x720")
        ventana_documentacion.minsize(760, 560)
        ventana_documentacion.resizable(True, True)
        ventana_documentacion.lift()

        marco = ttk.Frame(ventana_documentacion, padding=14)
        marco.pack(fill=tk.BOTH, expand=True)
        marco.rowconfigure(2, weight=1)
        marco.columnconfigure(0, weight=1)

        fuente_titulo_secundaria = tkfont.Font(
            family=tkfont.nametofont("TkDefaultFont").actual("family"),
            size=13,
            weight="bold",
        )

        ttk.Label(marco, text="Documentación de controles", font=fuente_titulo_secundaria).grid(
            row=0,
            column=0,
            sticky=tk.W,
            pady=(0, 10),
        )

        marco_busqueda = ttk.Frame(marco)
        marco_busqueda.grid(row=1, column=0, sticky=tk.EW, pady=(0, 10))
        marco_busqueda.columnconfigure(1, weight=1)

        ttk.Label(marco_busqueda, text="Buscar en todas las pestañas:").grid(row=0, column=0, sticky=tk.W)
        busqueda_var = tk.StringVar()
        entrada_busqueda = ttk.Entry(marco_busqueda, textvariable=busqueda_var)
        entrada_busqueda.grid(row=0, column=1, sticky=tk.EW, padx=(10, 10))
        etiqueta_resultados = ttk.Label(marco_busqueda, text="Sin búsqueda activa")
        etiqueta_resultados.grid(row=0, column=2, sticky=tk.E)

        pantalla_completa_var = tk.BooleanVar(value=False)
        geometria_normal = {"valor": ventana_documentacion.geometry()}

        def cambiar_pantalla_completa() -> None:
            """Activa o desactiva el modo de pantalla completa de la ventana de documentación."""
            nuevo_estado = not pantalla_completa_var.get()

            ventana_documentacion.update_idletasks()
            if nuevo_estado:
                geometria_normal["valor"] = ventana_documentacion.geometry()
                if os.name == "nt":
                    aplicado = False
                    for accion in (
                        lambda: ventana_documentacion.state("zoomed"),
                        lambda: ventana_documentacion.attributes("-fullscreen", True),
                        lambda: ventana_documentacion.wm_attributes("-fullscreen", True),
                    ):
                        try:
                            accion()
                            aplicado = True
                            break
                        except tk.TclError:
                            continue

                    if not aplicado:
                        ancho = ventana_documentacion.winfo_screenwidth()
                        alto = ventana_documentacion.winfo_screenheight()
                        ventana_documentacion.geometry(f"{ancho}x{alto}+0+0")
                else:
                    ancho = ventana_documentacion.winfo_screenwidth()
                    alto = ventana_documentacion.winfo_screenheight()

                    try:
                        ventana_documentacion.overrideredirect(True)
                    except tk.TclError:
                        pass

                    try:
                        ventana_documentacion.geometry(f"{ancho}x{alto}+0+0")
                    except tk.TclError:
                        pass

                    try:
                        ventana_documentacion.attributes("-topmost", True)
                        ventana_documentacion.attributes("-topmost", False)
                    except tk.TclError:
                        pass

                pantalla_completa_var.set(True)
            else:
                if os.name == "nt":
                    for accion in (
                        lambda: ventana_documentacion.state("normal"),
                        lambda: ventana_documentacion.attributes("-fullscreen", False),
                        lambda: ventana_documentacion.wm_attributes("-fullscreen", False),
                    ):
                        try:
                            accion()
                        except tk.TclError:
                            continue
                else:
                    try:
                        ventana_documentacion.overrideredirect(False)
                    except tk.TclError:
                        pass

                try:
                    ventana_documentacion.geometry(geometria_normal["valor"])
                except tk.TclError:
                    pass

                pantalla_completa_var.set(False)

            ventana_documentacion.update_idletasks()
            ventana_documentacion.lift()
            ventana_documentacion.focus_force()
            boton_pantalla_completa.configure(
                text="Salir de pantalla completa" if pantalla_completa_var.get() else "Pantalla completa"
            )

        def salir_pantalla_completa(_evento: object | None = None) -> None:
            """Sale del modo de pantalla completa si está activo."""
            if pantalla_completa_var.get():
                cambiar_pantalla_completa()

        boton_pantalla_completa = ttk.Button(
            marco_busqueda,
            text="Pantalla completa",
            command=cambiar_pantalla_completa,
        )
        boton_pantalla_completa.grid(row=0, column=3, sticky=tk.E, padx=(10, 0))

        cuaderno = ttk.Notebook(marco)
        cuaderno.grid(row=2, column=0, sticky=tk.NSEW)

        pestañas_documentacion: list[dict[str, object]] = []
        for titulo, contenido in self._separar_documentacion_en_pestanas(self._obtener_documentacion_controles()):
            panel = ttk.Frame(cuaderno, padding=8)
            panel.rowconfigure(0, weight=1)
            panel.columnconfigure(0, weight=1)

            cuadro_documentacion = tk.Text(
                panel,
                wrap=tk.WORD,
                relief=tk.FLAT,
                borderwidth=0,
                padx=10,
                pady=10,
                background="#F8FAFB",
                foreground="#12344D",
            )
            cuadro_documentacion.grid(row=0, column=0, sticky=tk.NSEW)

            barra_vertical = ttk.Scrollbar(panel, orient=tk.VERTICAL, command=cuadro_documentacion.yview)
            barra_vertical.grid(row=0, column=1, sticky=tk.NS)
            cuadro_documentacion.configure(yscrollcommand=barra_vertical.set)

            cuadro_documentacion.insert("1.0", contenido)
            cuadro_documentacion.tag_configure("busqueda", background="#FFF59D", foreground="#000000")
            cuadro_documentacion.tag_configure("busqueda_actual", background="#F9A825", foreground="#000000")
            cuadro_documentacion.configure(state="disabled")

            cuaderno.add(panel, text=titulo)
            pestañas_documentacion.append(
                {
                    "titulo": titulo,
                    "panel": panel,
                    "texto": cuadro_documentacion,
                }
            )

        def actualizar_busqueda(_evento: object | None = None) -> None:
            """Busca simultáneamente en todas las pestañas y resalta coincidencias."""
            consulta = busqueda_var.get().strip()
            total_coincidencias = 0
            resumen_pestañas: list[str] = []
            primera_pestaña_con_resultado: ttk.Frame | None = None

            for pestaña in pestañas_documentacion:
                cuadro = cast(tk.Text, pestaña["texto"])
                cuadro.tag_remove("busqueda", "1.0", tk.END)
                cuadro.tag_remove("busqueda_actual", "1.0", tk.END)

                if not consulta:
                    continue

                inicio = "1.0"
                coincidencias_pestaña = 0
                primera_coincidencia: str | None = None
                while True:
                    posicion = cuadro.search(consulta, inicio, stopindex=tk.END, nocase=True)
                    if not posicion:
                        break
                    final = f"{posicion}+{len(consulta)}c"
                    cuadro.tag_add("busqueda", posicion, final)
                    if primera_coincidencia is None:
                        primera_coincidencia = posicion
                    coincidencias_pestaña += 1
                    total_coincidencias += 1
                    inicio = final

                if coincidencias_pestaña:
                    resumen_pestañas.append(f"{pestaña['titulo']}: {coincidencias_pestaña}")
                    if primera_pestaña_con_resultado is None:
                        primera_pestaña_con_resultado = cast(ttk.Frame, pestaña["panel"])
                        if primera_coincidencia is not None:
                            cuadro.tag_add("busqueda_actual", primera_coincidencia, f"{primera_coincidencia}+{len(consulta)}c")
                            cuadro.see(primera_coincidencia)

            if not consulta:
                etiqueta_resultados.configure(text="Sin búsqueda activa")
                return

            if primera_pestaña_con_resultado is not None:
                cuaderno.select(primera_pestaña_con_resultado)

            if total_coincidencias:
                etiqueta_resultados.configure(text=f"{total_coincidencias} coincidencia(s) | {'; '.join(resumen_pestañas[:4])}")
            else:
                etiqueta_resultados.configure(text="Sin coincidencias")

        entrada_busqueda.bind("<KeyRelease>", actualizar_busqueda)
        entrada_busqueda.focus_set()
        ventana_documentacion.bind("<F11>", lambda _evento: cambiar_pantalla_completa())
        ventana_documentacion.bind("<Escape>", salir_pantalla_completa)

        ttk.Button(marco, text="Cerrar", command=ventana_documentacion.destroy).grid(
            row=3,
            column=0,
            sticky=tk.E,
            pady=(10, 0),
        )

    def _cargar_logo_sobre(self) -> ImageTk.PhotoImage | None:
        """Carga el logotipo de la aplicación para la ventana "Sobre" si el archivo existe."""
        ruta_logo = Path(__file__).resolve().parent.parent / "img" / "logo.png"
        if not ruta_logo.exists():
            return None

        try:
            with Image.open(ruta_logo) as imagen_original:
                imagen_original.thumbnail((280, 180))
                self.imagen_logo_sobre = ImageTk.PhotoImage(imagen_original.copy())
        except (tk.TclError, OSError):
            self.imagen_logo_sobre = None

        return self.imagen_logo_sobre

    def _abrir_repositorio_web(self) -> None:
        """Abre el repositorio del proyecto en el navegador web predeterminado del sistema."""
        webbrowser.open("https://github.com/sapoclay/auditorria", new=2)

    def _abrir_ventana_sobre(self) -> None:
        """Muestra una ventana con el logo, descripción y acceso al repositorio del proyecto."""
        ventana_sobre = tk.Toplevel(self.raiz)
        ventana_sobre.title(f"Sobre {NOMBRE_APLICACION}")
        ventana_sobre.geometry("640x500")
        ventana_sobre.minsize(580, 440)
        ventana_sobre.transient(self.raiz)

        contenedor = ttk.Frame(ventana_sobre)
        contenedor.pack(fill=tk.BOTH, expand=True)
        contenedor.rowconfigure(0, weight=1)
        contenedor.columnconfigure(0, weight=1)

        lienzo = tk.Canvas(contenedor, highlightthickness=0, background="#F2F5F7")
        barra_vertical = ttk.Scrollbar(contenedor, orient=tk.VERTICAL, command=lienzo.yview)
        lienzo.configure(yscrollcommand=barra_vertical.set)
        lienzo.grid(row=0, column=0, sticky=tk.NSEW)
        barra_vertical.grid(row=0, column=1, sticky=tk.NS)

        marco = ttk.Frame(lienzo, padding=18)
        marco.columnconfigure(0, weight=1)
        ventana_marco = lienzo.create_window((0, 0), window=marco, anchor=tk.NW)

        def actualizar_region_desplazamiento(_evento: object | None = None) -> None:
            """Sincroniza el área desplazable con el contenido real del panel."""
            lienzo.configure(scrollregion=lienzo.bbox("all"))

        def ajustar_ancho_marco(evento: tk.Event[tk.Misc]) -> None:
            """Hace que el contenido use todo el ancho disponible del lienzo."""
            lienzo.itemconfigure(ventana_marco, width=evento.width)

        marco.bind("<Configure>", actualizar_region_desplazamiento)
        lienzo.bind("<Configure>", ajustar_ancho_marco)

        fuente_titulo_secundaria = tkfont.Font(
            family=tkfont.nametofont("TkDefaultFont").actual("family"),
            size=14,
            weight="bold",
        )

        logo = self._cargar_logo_sobre()
        if logo is not None:
            ttk.Label(marco, image=logo).grid(row=0, column=0, pady=(0, 12))
        else:
            ttk.Label(marco, text=NOMBRE_APLICACION, font=fuente_titulo_secundaria).grid(row=0, column=0, pady=(0, 12))

        ttk.Label(marco, text=NOMBRE_APLICACION, font=fuente_titulo_secundaria).grid(row=1, column=0, pady=(0, 8))
        ttk.Label(
            marco,
            text=(
                "AudiTorría es una herramienta de auditoría de red y seguridad que permite revisar "
                "equipos individuales, rangos de red y el propio equipo local. Genera informes en PDF, "
                "muestra resultados en una interfaz gráfica y ayuda a identificar servicios expuestos, "
                "configuraciones relevantes y hallazgos básicos de seguridad."
            ),
            wraplength=520,
            justify=tk.CENTER,
        ).grid(row=2, column=0, pady=(0, 18))

        ttk.Button(
            marco,
            text="Abrir repositorio del proyecto",
            command=self._abrir_repositorio_web,
        ).grid(row=3, column=0, pady=(0, 10))

        ttk.Label(
            marco,
            text="https://github.com/sapoclay/auditorria",
            foreground="#1F5A7A",
        ).grid(row=4, column=0, pady=(0, 18))

        # Se habilita rueda del ratón para mejorar la navegación vertical en la ventana.
        def desplazar_con_rueda(evento: tk.Event[tk.Misc]) -> None:
            """Desplaza el contenido con la rueda del ratón en Windows y Linux."""
            if getattr(evento, "delta", 0):
                lienzo.yview_scroll(int(-1 * (evento.delta / 120)), "units")
            elif getattr(evento, "num", None) == 4:
                lienzo.yview_scroll(-1, "units")
            elif getattr(evento, "num", None) == 5:
                lienzo.yview_scroll(1, "units")

        lienzo.bind_all("<MouseWheel>", desplazar_con_rueda)
        lienzo.bind_all("<Button-4>", desplazar_con_rueda)
        lienzo.bind_all("<Button-5>", desplazar_con_rueda)

        def liberar_eventos_rueda(_evento: object | None = None) -> None:
            """Libera los enlaces globales de la rueda al cerrar la ventana Sobre."""
            lienzo.unbind_all("<MouseWheel>")
            lienzo.unbind_all("<Button-4>")
            lienzo.unbind_all("<Button-5>")

        def cerrar_ventana_sobre() -> None:
            """Cierra la ventana y limpia los eventos temporales asociados al scroll."""
            liberar_eventos_rueda()
            ventana_sobre.destroy()

        ttk.Button(marco, text="Cerrar", command=cerrar_ventana_sobre).grid(row=5, column=0)

        ventana_sobre.protocol("WM_DELETE_WINDOW", cerrar_ventana_sobre)

    def _configurar_colores_tabla(self, tabla: ttk.Treeview) -> None:
        """Define una paleta coherente para representar estado y nivel de riesgo en filas."""
        tabla.tag_configure("riesgo_alto", background="#FADBD8", foreground="#7B241C")
        tabla.tag_configure("riesgo_medio", background="#FCF3CF", foreground="#7D6608")
        tabla.tag_configure("riesgo_bajo", background="#D5F5E3", foreground="#145A32")
        tabla.tag_configure("sin_respuesta", background="#E5E7E9", foreground="#424949")

    def _actualizar_estado_campos(self) -> None:
        """Activa o desactiva los campos según el tipo de objetivo elegido."""
        modo = self.modo_objetivo_var.get()
        self.entrada_red.configure(state="normal" if modo == "red" else "disabled")
        self.entrada_ips.configure(state="normal" if modo == "ips" else "disabled")

    def _seleccionar_pdf(self) -> None:
        """Permite elegir desde un diálogo gráfico la ubicación del informe PDF."""
        ruta = filedialog.asksaveasfilename(
            title="Guardar informe PDF",
            defaultextension=".pdf",
            filetypes=[("Documento PDF", "*.pdf")],
            initialfile=Path(self.salida_var.get()).name,
        )
        if ruta:
            self.salida_var.set(ruta)

    def _obtener_parametros(self) -> ParametrosAuditoria:
        """Lee la información del formulario y la transforma en parámetros de auditoría."""
        # Según la opción elegida, se prepara la lista de equipos a revisar.
        if self.modo_objetivo_var.get() == "red":
            red = self.red_var.get().strip()
            red_normalizada = normalizar_red_para_auditoria(red)
            objetivos = obtener_objetivos_desde_red(red)
            descripcion = f"Red auditada: {red_normalizada}"
            modo_auditoria = "red"
        elif self.modo_objetivo_var.get() == "ips":
            ips = self.ips_var.get().strip()
            objetivos = obtener_objetivos_desde_ips(ips)
            descripcion = f"IPs auditadas: {', '.join(objetivos)}"
            modo_auditoria = "red"
        else:
            objetivos = ["127.0.0.1"]
            descripcion = "Equipo local auditado"
            modo_auditoria = "local"

        # A partir de aquí se juntan todos los datos en un único objeto.
        return ParametrosAuditoria(
            objetivos=objetivos,
            descripcion_objetivo=descripcion,
            puertos=obtener_puertos(self.puertos_var.get().strip()),
            ruta_pdf=construir_ruta_pdf(self.salida_var.get().strip()),
            concurrencia=max(1, int(self.concurrencia_var.get())),
            modo_auditoria=modo_auditoria,
        )

    def _iniciar_auditoria(self) -> None:
        """Valida el formulario y arranca la auditoría en un hilo secundario."""
        # Si ya hay una revisión en marcha, no se lanza otra por encima.
        if self.hilo_auditoria and self.hilo_auditoria.is_alive():
            messagebox.showinfo(NOMBRE_APLICACION, "Ya hay una auditoría en ejecución.")
            return

        try:
            parametros = self._obtener_parametros()
        except Exception as error:  # noqa: BLE001
            messagebox.showerror(NOMBRE_APLICACION, str(error))
            return

        self._limpiar_registro()
        self._reiniciar_resultados()
        self._escribir_registro(f"Objetivos preparados: {len(parametros.objetivos)}")
        if parametros.modo_auditoria == "local":
            self._escribir_registro("Modo seleccionado: auditoría local avanzada del equipo")
        else:
            self._escribir_registro(f"Puertos configurados: {', '.join(str(puerto) for puerto in parametros.puertos)}")
        self._escribir_registro("Iniciando auditoría...")
        self.estado_var.set("Ejecutando auditoría...")
        self.porcentaje_var.set("0%")
        self.boton_ejecutar.configure(state="disabled")
        self.barra_progreso.configure(value=0)

        # La revisión real se manda a otro hilo para que la ventana no se quede bloqueada.
        self.hilo_auditoria = threading.Thread(
            target=self._ejecutar_auditoria_en_segundo_plano,
            args=(parametros,),
            daemon=True,
        )
        self.hilo_auditoria.start()

    def _ejecutar_auditoria_en_segundo_plano(self, parametros: ParametrosAuditoria) -> None:
        """Ejecuta la auditoría fuera del hilo de la interfaz y publica los resultados en una cola."""
        try:
            resumen = ejecutar_auditoria_completa(
                parametros,
                notificar_progreso=lambda progreso: self.cola_mensajes.put(("progreso", progreso)),
            )
            self.cola_mensajes.put(("finalizado", resumen))
        except Exception as error:  # noqa: BLE001
            detalle = "".join(traceback.format_exception_only(type(error), error)).strip()
            self.cola_mensajes.put(("error", detalle))

    def _programar_revision_cola(self) -> None:
        """Revisa periódicamente la cola compartida para actualizar la interfaz."""
        self._procesar_cola()
        self.raiz.after(150, self._programar_revision_cola)

    def _procesar_cola(self) -> None:
        """Consume todos los mensajes pendientes enviados por el hilo de trabajo."""
        # La cola sirve para pasar mensajes del hilo de auditoría a la ventana.
        while True:
            try:
                tipo, contenido = self.cola_mensajes.get_nowait()
            except queue.Empty:
                break

            if tipo == "progreso":
                self._manejar_progreso(cast(ProgresoAuditoria, contenido))
            elif tipo == "finalizado":
                self._manejar_finalizacion(cast(ResumenAuditoria, contenido))
            elif tipo == "error":
                self._manejar_error(str(contenido))

    def _manejar_progreso(self, progreso: ProgresoAuditoria) -> None:
        """Actualiza la barra de progreso y añade el equipo procesado a la tabla visual."""
        self.barra_progreso.configure(value=progreso.porcentaje)
        self.porcentaje_var.set(f"{progreso.porcentaje:.0f}%")
        self.estado_var.set(progreso.mensaje)
        self._escribir_registro(f"{progreso.mensaje} ({progreso.porcentaje:.0f}%)")

        # Si ya llegó información de un equipo, se guarda y se refresca la tabla.
        if progreso.resultado_equipo is not None:
            self._registrar_resultado(progreso.resultado_equipo)
            self._aplicar_filtros_tabla()

    def _manejar_finalizacion(self, resumen: ResumenAuditoria) -> None:
        """Actualiza la interfaz cuando la auditoría termina con éxito."""
        self.barra_progreso.configure(value=100)
        self.porcentaje_var.set("100%")
        self.boton_ejecutar.configure(state="normal")
        self.resultados_actuales = list(resumen.resultados)
        self.resultados_por_ip = {resultado.ip: resultado for resultado in resumen.resultados}
        self._aplicar_filtros_tabla()
        self.estado_var.set(f"Auditoría finalizada. PDF: {resumen.parametros.ruta_pdf}")
        self._escribir_registro("Auditoría completada correctamente.")
        self._escribir_registro(f"Informe generado en: {resumen.parametros.ruta_pdf}")
        messagebox.showinfo(NOMBRE_APLICACION, f"Informe generado en:\n{resumen.parametros.ruta_pdf}")

    def _manejar_error(self, mensaje: str) -> None:
        """Restaura el estado de la ventana y muestra el error al usuario."""
        self.boton_ejecutar.configure(state="normal")
        self.estado_var.set("La auditoría terminó con errores.")
        self._escribir_registro(f"Error: {mensaje}")
        messagebox.showerror(NOMBRE_APLICACION, mensaje)

    def _limpiar_registro(self) -> None:
        """Vacía la consola interna para una nueva ejecución limpia."""
        self.texto_registro.delete("1.0", tk.END)

    def _reiniciar_resultados(self) -> None:
        """Vacía los resultados en memoria y limpia la tabla antes de una nueva auditoría."""
        self.resultados_actuales.clear()
        self.resultados_por_ip.clear()
        self._limpiar_tabla_resultados()

    def _limpiar_tabla_resultados(self) -> None:
        """Elimina las filas visuales para poder reconstruir la tabla según los filtros."""
        for elemento in self.tabla_resultados.get_children():
            self.tabla_resultados.delete(elemento)

    def _registrar_resultado(self, resultado: ResultadoEquipo) -> None:
        """Guarda o reemplaza en memoria el resultado de un equipo ya procesado."""
        # Si la IP ya estaba guardada, se sustituye por la versión más reciente.
        if resultado.ip in self.resultados_por_ip:
            for indice, resultado_existente in enumerate(self.resultados_actuales):
                if resultado_existente.ip == resultado.ip:
                    self.resultados_actuales[indice] = resultado
                    break
        else:
            self.resultados_actuales.append(resultado)

        self.resultados_por_ip[resultado.ip] = resultado

    def _agregar_resultado_tabla(self, resultado: ResultadoEquipo) -> None:
        """Inserta una fila con los datos principales del equipo visible en la tabla."""
        estado = "Activo" if resultado.activo else "Sin respuesta"
        riesgo, etiqueta_color = self._obtener_riesgo_y_etiqueta(resultado)
        puertos = ", ".join(str(puerto.numero) for puerto in resultado.puertos_abiertos) or "Ninguno"
        self.tabla_resultados.insert(
            "",
            tk.END,
            values=(
                resultado.ip,
                estado,
                riesgo,
                resultado.nombre_host,
                resultado.tiempo_respuesta_ms,
                puertos,
                resultado.ttl,
            ),
            tags=(etiqueta_color,),
        )

    def _obtener_riesgo_y_etiqueta(self, resultado: ResultadoEquipo) -> tuple[str, str]:
        """Clasifica el resultado del equipo para elegir texto de riesgo y color de fila."""
        puertos_abiertos = {puerto.numero for puerto in resultado.puertos_abiertos}
        texto_hallazgos = " ".join(resultado.hallazgos_host).upper()
        texto_cves = " ".join(resultado.vulnerabilidades_cve).upper()

        # Primero se mira si el equipo ni siquiera respondió.
        if not resultado.activo and not puertos_abiertos:
            return "Sin respuesta", "sin_respuesta"

        # Después se da prioridad a los hallazgos más graves y a los CVEs.
        if "[CRITICO]" in texto_cves or "[CVSS 9." in texto_cves or "[CVSS 10." in texto_cves:
            return "Alto", "riesgo_alto"

        if "[ALTO]" in texto_cves or "[CVSS 7." in texto_cves or "[CVSS 8." in texto_cves:
            return "Alto", "riesgo_alto"

        if "[ALTO]" in texto_hallazgos:
            return "Alto", "riesgo_alto"

        if "[MEDIO]" in texto_hallazgos:
            return "Medio", "riesgo_medio"

        puertos_riesgo_alto = {23, 445, 3389, 1433, 1521, 3306, 5432}
        puertos_riesgo_medio = {21, 22, 25, 80, 110, 139, 143, 587, 5900, 6379, 8080, 8443}

        # Si no hay avisos claros, se usa una regla sencilla basada en puertos expuestos.
        if puertos_abiertos & puertos_riesgo_alto:
            return "Alto", "riesgo_alto"

        if 80 in puertos_abiertos and 443 not in puertos_abiertos:
            return "Alto", "riesgo_alto"

        if len(puertos_abiertos) >= 5:
            return "Alto", "riesgo_alto"

        if puertos_abiertos & puertos_riesgo_medio:
            return "Medio", "riesgo_medio"

        if len(puertos_abiertos) >= 1:
            return "Bajo", "riesgo_bajo"

        return "Bajo", "riesgo_bajo"

    def _aplicar_filtros_tabla(self, _evento: object | None = None) -> None:
        """Reconstruye la tabla aplicando búsqueda por texto y filtros de estado."""
        texto_busqueda = self.filtro_texto_var.get().strip().lower()
        estado_seleccionado = self.filtro_estado_var.get()
        solo_con_puertos = self.filtro_solo_puertos_var.get()

        self._limpiar_tabla_resultados()

        for resultado in self.resultados_actuales:
            # Se junta casi toda la información en un solo texto para que el buscador
            # encuentre coincidencias aunque el dato esté en otra sección del resultado.
            estado = "Activo" if resultado.activo else "Sin respuesta"
            riesgo, _ = self._obtener_riesgo_y_etiqueta(resultado)
            puertos_texto = ", ".join(str(puerto.numero) for puerto in resultado.puertos_abiertos) or "ninguno"
            servicios_texto = ", ".join(puerto.servicio for puerto in resultado.puertos_abiertos).lower()
            texto_completo = " ".join(
                [
                    resultado.ip.lower(),
                    estado.lower(),
                    riesgo.lower(),
                    resultado.nombre_host.lower(),
                    puertos_texto.lower(),
                    servicios_texto,
                    " ".join(resultado.informacion_sistema).lower(),
                    " ".join(resultado.hallazgos_host).lower(),
                    " ".join(resultado.comprobaciones_adicionales).lower(),
                    " ".join(resultado.versiones_servicios).lower(),
                    " ".join(resultado.vulnerabilidades_cve).lower(),
                    " ".join(resultado.observaciones_seguridad).lower(),
                ]
            )

            # Cada filtro descarta lo que no encaja antes de añadir la fila.
            if texto_busqueda and texto_busqueda not in texto_completo:
                continue
            if estado_seleccionado != "Todos" and estado != estado_seleccionado:
                continue
            if solo_con_puertos and not resultado.puertos_abiertos:
                continue

            self._agregar_resultado_tabla(resultado)

    def _limpiar_filtros(self) -> None:
        """Restablece los filtros a su estado inicial y recarga la tabla completa."""
        self.filtro_texto_var.set("")
        self.filtro_estado_var.set("Todos")
        self.filtro_solo_puertos_var.set(False)
        self._aplicar_filtros_tabla()

    def _mostrar_detalle_equipo(self, _evento: object | None = None) -> None:
        """Abre una ventana con el detalle completo del equipo sobre el que se hizo doble clic."""
        # Se toma la fila seleccionada y se busca su resultado completo en memoria.
        seleccion = self.tabla_resultados.focus()
        if not seleccion:
            return

        valores = self.tabla_resultados.item(seleccion, "values")
        if not valores:
            return

        ip = str(valores[0])
        resultado = self.resultados_por_ip.get(ip)
        if resultado is None:
            return

        riesgo, etiqueta_color = self._obtener_riesgo_y_etiqueta(resultado)

        # Esta ventana enseña toda la información de un equipo sin recortar tanto como la tabla.
        ventana_detalle = tk.Toplevel(self.raiz)
        ventana_detalle.title(f"Información del equipo - {resultado.ip}")
        ventana_detalle.geometry("760x520")
        ventana_detalle.minsize(680, 460)
        ventana_detalle.transient(self.raiz)

        marco = ttk.Frame(ventana_detalle, padding=14)
        marco.pack(fill=tk.BOTH, expand=True)
        marco.rowconfigure(1, weight=1)
        marco.columnconfigure(0, weight=1)

        fuente_titulo_secundaria = tkfont.Font(
            family=tkfont.nametofont("TkDefaultFont").actual("family"),
            size=13,
            weight="bold",
        )

        ttk.Label(marco, text=f"Equipo revisado: {resultado.ip}", font=fuente_titulo_secundaria).grid(
            row=0,
            column=0,
            sticky=tk.W,
            pady=(0, 10),
        )

        cuadro_detalle = tk.Text(marco, wrap="word", bg="#101821", fg="#E8EEF2")
        cuadro_detalle.grid(row=1, column=0, sticky=tk.NSEW)
        barra = ttk.Scrollbar(marco, orient=tk.VERTICAL, command=cuadro_detalle.yview)
        barra.grid(row=1, column=1, sticky=tk.NS)
        cuadro_detalle.configure(yscrollcommand=barra.set)

        estado = "Activo" if resultado.activo else "Sin respuesta"
        puertos_abiertos = (
            "\n".join(
                f"- {puerto.numero}/{puerto.estado}: {puerto.servicio}"
                for puerto in resultado.puertos_abiertos
            )
            or "- No se encontraron puertos abiertos en la revisión"
        )
        observaciones = (
            "\n".join(f"- {observacion}" for observacion in resultado.observaciones_seguridad)
            or "- Sin avisos importantes"
        )
        informacion_sistema = (
            "\n".join(f"- {dato}" for dato in resultado.informacion_sistema)
            or "- Sin más información del sistema"
        )
        hallazgos_host = (
            "\n".join(f"- {hallazgo}" for hallazgo in resultado.hallazgos_host)
            or "- Sin hallazgos locales destacados"
        )
        comprobaciones_adicionales = (
            "\n".join(f"- {comprobacion}" for comprobacion in resultado.comprobaciones_adicionales)
            or "- No se pudieron obtener más comprobaciones"
        )
        versiones_servicios = (
            "\n".join(f"- {version}" for version in resultado.versiones_servicios)
            or "- No se encontraron versiones concretas de programas o servicios"
        )
        vulnerabilidades_cve = (
            "\n".join(f"- {vulnerabilidad}" for vulnerabilidad in resultado.vulnerabilidades_cve)
            or "- No se encontraron fallos conocidos relacionados con esas versiones"
        )
        detalle_error = resultado.error or "Sin errores registrados"

        # Se compone un resumen textual completo para facilitar revisión y copia del contenido.
        detalle = (
            f"IP: {resultado.ip}\n"
            f"Estado: {estado}\n"
            f"Nivel de riesgo: {riesgo}\n"
            f"Host resuelto: {resultado.nombre_host}\n"
            f"Tiempo de respuesta: {resultado.tiempo_respuesta_ms}\n"
            f"Categoría de latencia: {resultado.categoria_latencia}\n"
            f"TTL: {resultado.ttl}\n\n"
            f"Sistema operativo probable: {resultado.sistema_operativo_probable}\n\n"
            f"Información del sistema:\n{informacion_sistema}\n\n"
            f"Puertos abiertos encontrados:\n{puertos_abiertos}\n\n"
            f"Comprobaciones extra:\n{comprobaciones_adicionales}\n\n"
            f"Versiones encontradas:\n{versiones_servicios}\n\n"
            f"Fallos de seguridad conocidos:\n{vulnerabilidades_cve}\n\n"
            f"Hallazgos del equipo:\n{hallazgos_host}\n\n"
            f"Avisos importantes:\n{observaciones}\n\n"
            f"Detalle técnico:\n{detalle_error}\n"
        )

        cuadro_detalle.insert("1.0", detalle)
        cuadro_detalle.configure(state="disabled")
        cuadro_detalle.tag_configure(etiqueta_color, spacing1=4)

        ttk.Button(marco, text="Cerrar", command=ventana_detalle.destroy).grid(row=2, column=0, sticky=tk.E, pady=(10, 0))

    def _abrir_leyenda_colores(self) -> None:
        """Muestra una tabla con la leyenda de colores utilizada en la tabla principal."""
        ventana_leyenda = tk.Toplevel(self.raiz)
        ventana_leyenda.title("Ayuda - Leyenda de colores")
        ventana_leyenda.geometry("700x320")
        ventana_leyenda.minsize(640, 280)
        ventana_leyenda.transient(self.raiz)

        marco = ttk.Frame(ventana_leyenda, padding=14)
        marco.pack(fill=tk.BOTH, expand=True)
        marco.rowconfigure(1, weight=1)
        marco.columnconfigure(0, weight=1)

        fuente_titulo_secundaria = tkfont.Font(
            family=tkfont.nametofont("TkDefaultFont").actual("family"),
            size=13,
            weight="bold",
        )

        ttk.Label(marco, text="Leyenda de colores", font=fuente_titulo_secundaria).grid(
            row=0,
            column=0,
            sticky=tk.W,
            pady=(0, 10),
        )

        columnas = ("nivel", "color", "descripcion")
        tabla_leyenda = ttk.Treeview(marco, columns=columnas, show="headings", height=6)
        tabla_leyenda.heading("nivel", text="Nivel / Estado")
        tabla_leyenda.heading("color", text="Color aplicado")
        tabla_leyenda.heading("descripcion", text="Interpretación")
        tabla_leyenda.column("nivel", width=150, anchor=tk.W)
        tabla_leyenda.column("color", width=140, anchor=tk.CENTER)
        tabla_leyenda.column("descripcion", width=360, anchor=tk.W)
        tabla_leyenda.grid(row=1, column=0, sticky=tk.NSEW)
        self._configurar_colores_tabla(tabla_leyenda)

        leyendas = [
            (
                "Alto",
                "Rojo suave",
                "Servicios expuestos de mayor riesgo, varios puertos abiertos o HTTP sin HTTPS.",
                "riesgo_alto",
            ),
            (
                "Medio",
                "Amarillo suave",
                "Exposición moderada de servicios que conviene revisar con atención.",
                "riesgo_medio",
            ),
            (
                "Bajo",
                "Verde suave",
                "Sin exposición significativa dentro de los puertos auditados o exposición limitada.",
                "riesgo_bajo",
            ),
            (
                "Sin respuesta",
                "Gris",
                "El equipo no respondió al ping y no mostró puertos abiertos en la lista comprobada.",
                "sin_respuesta",
            ),
        ]

        for nivel, color, descripcion, etiqueta in leyendas:
            tabla_leyenda.insert("", tk.END, values=(nivel, color, descripcion), tags=(etiqueta,))

        ttk.Label(
            marco,
            text="La clasificación es orientativa y se basa en la conectividad y los puertos detectados durante la auditoría.",
        ).grid(row=2, column=0, sticky=tk.W, pady=(10, 0))

        ttk.Button(marco, text="Cerrar", command=ventana_leyenda.destroy).grid(row=3, column=0, sticky=tk.E, pady=(10, 0))

    def _escribir_registro(self, mensaje: str) -> None:
        """Añade una línea al registro visual de la interfaz."""
        self.texto_registro.insert(tk.END, f"{mensaje}\n")
        self.texto_registro.see(tk.END)

    def _abrir_carpeta_reportes(self) -> None:
        """Abre la carpeta donde se almacenan los informes generados."""
        carpeta = Path(self.salida_var.get()).expanduser().resolve().parent
        carpeta.mkdir(parents=True, exist_ok=True)

        try:
            if os.name == "nt":
                os.startfile(str(carpeta))  # type: ignore[attr-defined]
            else:
                import subprocess

                subprocess.run(["xdg-open", str(carpeta)], check=False)
        except Exception as error:  # noqa: BLE001
            messagebox.showerror(NOMBRE_APLICACION, f"No se pudo abrir la carpeta: {error}")

    def ejecutar(self) -> int:
        """Arranca el bucle principal de Tkinter."""
        self.raiz.mainloop()
        return 0



def hay_entorno_grafico() -> bool:
    """Comprueba si el sistema parece tener soporte para mostrar una ventana gráfica."""
    return os.name == "nt" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))



def ejecutar_modo_grafico() -> int:
    """Crea y muestra la interfaz gráfica principal de AudiTorría."""
    ventana = VentanaPrincipal()
    return ventana.ejecutar()
