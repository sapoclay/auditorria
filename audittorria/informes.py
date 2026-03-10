from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .configuracion import NOMBRE_APLICACION
from .modelos import ResultadoEquipo, ResumenAuditoria


# --------------------------------------------------------------------------------------
# Funciones de composición del PDF.
# --------------------------------------------------------------------------------------


def crear_estilos_pdf():
    """Define estilos visuales reutilizables para mantener uniforme el informe."""
    estilos_base = getSampleStyleSheet()
    estilos_base.add(
        ParagraphStyle(
            name="TituloCentro",
            parent=estilos_base["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#12344D"),
            spaceAfter=14,
        )
    )
    estilos_base.add(
        ParagraphStyle(
            name="SubtituloAzul",
            parent=estilos_base["Heading2"],
            alignment=TA_LEFT,
            textColor=colors.HexColor("#1F5A7A"),
            spaceAfter=8,
        )
    )
    estilos_base.add(
        ParagraphStyle(
            name="TextoNormalEspaciado",
            parent=estilos_base["BodyText"],
            leading=15,
            spaceAfter=6,
        )
    )
    estilos_base.add(
        ParagraphStyle(
            name="CeldaTabla",
            parent=estilos_base["BodyText"],
            leading=10,
            fontSize=8,
            wordWrap="CJK",
            spaceAfter=0,
        )
    )
    return estilos_base



def ajustar_texto_largo(texto: str, longitud_segmento: int = 28) -> str:
    """Inserta puntos de corte en textos largos para evitar desbordes en celdas del PDF."""
    partes_ajustadas: list[str] = []
    for token in texto.split(" "):
        if len(token) <= longitud_segmento:
            partes_ajustadas.append(token)
            continue

        segmentos = [token[indice:indice + longitud_segmento] for indice in range(0, len(token), longitud_segmento)]
        partes_ajustadas.append("<br/>".join(segmentos))

    return " ".join(partes_ajustadas)



def celda_tabla(texto: str, estilos) -> Paragraph:
    """Convierte un texto a `Paragraph` para permitir salto de línea automático dentro de tablas."""
    texto_normalizado = ajustar_texto_largo(str(texto).replace("\n", "<br/>"))
    return Paragraph(texto_normalizado, estilos["CeldaTabla"])



def es_resultado_local(resultado: ResultadoEquipo) -> bool:
    """Determina si un resultado procede de la auditoría local del propio equipo."""
    return any(dato.strip().lower() == "modo de auditoría: local del equipo" for dato in resultado.informacion_sistema)



def obtener_ips_mostrables(resultado: ResultadoEquipo) -> str:
    """Obtiene la IP o conjunto de IPs más representativo para mostrar en el informe."""
    for dato in resultado.informacion_sistema:
        prefijo = "Direcciones IP detectadas:"
        if dato.startswith(prefijo):
            ips = dato.split(":", 1)[1].strip()
            if ips:
                return ips
    return resultado.ip



def obtener_titulo_equipo(resultado: ResultadoEquipo, indice: int) -> str:
    """Genera un título más claro para el bloque individual de cada resultado."""
    if es_resultado_local(resultado):
        return f"Equipo local: {obtener_ips_mostrables(resultado)}"
    return f"Equipo {indice}: {resultado.ip}"



def construir_tabla_resumen(resultados: list[ResultadoEquipo]) -> Table:
    """Genera una tabla compacta con el estado general de todos los equipos."""
    estilos = crear_estilos_pdf()
    filas: list[list[Any]] = [["IP", "Estado", "Host", "Puertos abiertos", "Tiempo ping"]]

    for resultado in resultados:
        filas.append(
            [
                celda_tabla(obtener_ips_mostrables(resultado), estilos),
                celda_tabla("Activo" if resultado.activo else "Sin respuesta ICMP", estilos),
                celda_tabla(resultado.nombre_host, estilos),
                celda_tabla(", ".join(str(puerto.numero) for puerto in resultado.puertos_abiertos) or "Ninguno", estilos),
                celda_tabla(resultado.tiempo_respuesta_ms, estilos),
            ]
        )

    tabla = Table(filas, repeatRows=1, colWidths=[3.0 * cm, 3.4 * cm, 4.4 * cm, 4.0 * cm, 3.0 * cm])
    tabla.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12344D")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#EAF2F8")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return tabla



def generar_pdf(resumen: ResumenAuditoria, ruta_pdf: Path | None = None) -> Path:
    """Construye el PDF final a partir de los resultados de la auditoría."""
    parametros = resumen.parametros
    resultados = resumen.resultados
    ruta_destino = ruta_pdf or parametros.ruta_pdf
    estilos = crear_estilos_pdf()

    documento = SimpleDocTemplate(
        str(ruta_destino),
        pagesize=A4,
        leftMargin=1.7 * cm,
        rightMargin=1.7 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title=f"Informe {NOMBRE_APLICACION}",
        author=NOMBRE_APLICACION,
    )

    elementos = []
    fecha_generacion = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    total_activos = sum(1 for resultado in resultados if resultado.activo)
    total_con_puertos = sum(1 for resultado in resultados if resultado.puertos_abiertos)
    total_hallazgos_host = sum(len(resultado.hallazgos_host) for resultado in resultados)
    total_cves = sum(len(resultado.vulnerabilidades_cve) for resultado in resultados)

    # Portada del informe con los datos generales de la auditoría.
    elementos.append(Paragraph(f"Informe de auditoría - {NOMBRE_APLICACION}", estilos["TituloCentro"]))
    elementos.append(Paragraph(f"<b>Fecha:</b> {fecha_generacion}", estilos["TextoNormalEspaciado"]))
    elementos.append(
        Paragraph(f"<b>Objetivo:</b> {parametros.descripcion_objetivo}", estilos["TextoNormalEspaciado"])
    )
    elementos.append(
        Paragraph(
            f"<b>Puertos revisados:</b> {', '.join(str(puerto) for puerto in parametros.puertos)}",
            estilos["TextoNormalEspaciado"],
        )
    )
    elementos.append(
        Paragraph(
            "<b>Nota:</b> Este informe refleja comprobaciones básicas de conectividad y exposición de servicios. "
            "Debe complementarse con revisión de configuración, credenciales, parches y registros.",
            estilos["TextoNormalEspaciado"],
        )
    )
    elementos.append(Spacer(1, 0.4 * cm))

    # Resumen ejecutivo para una lectura rápida por parte del operador.
    elementos.append(Paragraph("Resumen ejecutivo", estilos["SubtituloAzul"]))
    elementos.append(
        Paragraph(
            f"Se auditaron <b>{len(resultados)}</b> equipos. "
            f"Respondieron al ping <b>{total_activos}</b>, se detectaron puertos abiertos en <b>{total_con_puertos}</b> equipos "
            f"y se registraron <b>{total_hallazgos_host}</b> hallazgos locales adicionales. "
            f"Además, se identificaron <b>{total_cves}</b> referencias CVE priorizadas.",
            estilos["TextoNormalEspaciado"],
        )
    )
    elementos.append(construir_tabla_resumen(resultados))
    elementos.append(PageBreak())

    # Detalle individual para que cada equipo tenga su evidencia separada.
    for indice, resultado in enumerate(resultados, start=1):
        elementos.append(Paragraph(obtener_titulo_equipo(resultado, indice), estilos["SubtituloAzul"]))
        elementos.append(
            Paragraph(
                f"<b>Estado ICMP:</b> {'Activo' if resultado.activo else 'Sin respuesta'}<br/>"
                f"<b>IP(s) mostradas:</b> {obtener_ips_mostrables(resultado)}<br/>"
                f"<b>Tiempo de respuesta:</b> {resultado.tiempo_respuesta_ms}<br/>"
                f"<b>Categoría de latencia:</b> {resultado.categoria_latencia}<br/>"
                f"<b>TTL observado:</b> {resultado.ttl}<br/>"
                f"<b>Sistema operativo probable:</b> {resultado.sistema_operativo_probable}<br/>"
                f"<b>Nombre DNS inverso:</b> {resultado.nombre_host}",
                estilos["TextoNormalEspaciado"],
            )
        )

        if resultado.puertos_abiertos:
            filas_puertos: list[list[Any]] = [["Puerto", "Servicio", "Estado"]]
            for puerto in resultado.puertos_abiertos:
                filas_puertos.append(
                    [
                        celda_tabla(str(puerto.numero), estilos),
                        celda_tabla(puerto.servicio, estilos),
                        celda_tabla(puerto.estado, estilos),
                    ]
                )

            tabla_puertos = Table(filas_puertos, repeatRows=1, colWidths=[2.5 * cm, 8.0 * cm, 3.0 * cm])
            tabla_puertos.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F5A7A")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F6F7")]),
                    ]
                )
            )
            elementos.append(Paragraph("Puertos abiertos detectados", estilos["TextoNormalEspaciado"]))
            elementos.append(tabla_puertos)
        else:
            elementos.append(
                Paragraph(
                    "No se detectaron puertos abiertos dentro del conjunto auditado.",
                    estilos["TextoNormalEspaciado"],
                )
            )

        if resultado.comprobaciones_adicionales:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph("Comprobaciones adicionales", estilos["TextoNormalEspaciado"]))
            for comprobacion in resultado.comprobaciones_adicionales:
                elementos.append(Paragraph(f"• {comprobacion}", estilos["TextoNormalEspaciado"]))

        if resultado.versiones_servicios:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph("Versiones exactas de servicios detectadas", estilos["TextoNormalEspaciado"]))
            for version in resultado.versiones_servicios:
                elementos.append(Paragraph(f"• {version}", estilos["TextoNormalEspaciado"]))

        if resultado.vulnerabilidades_cve:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph("Vulnerabilidades CVE asociadas", estilos["TextoNormalEspaciado"]))
            for vulnerabilidad in resultado.vulnerabilidades_cve:
                elementos.append(Paragraph(f"• {vulnerabilidad}", estilos["TextoNormalEspaciado"]))

        if resultado.informacion_sistema:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph("Información del sistema", estilos["TextoNormalEspaciado"]))
            for dato in resultado.informacion_sistema:
                elementos.append(Paragraph(f"• {dato}", estilos["TextoNormalEspaciado"]))

        if resultado.hallazgos_host:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph("Hallazgos del host", estilos["TextoNormalEspaciado"]))
            for hallazgo in resultado.hallazgos_host:
                elementos.append(Paragraph(f"• {hallazgo}", estilos["TextoNormalEspaciado"]))

        if resultado.observaciones_seguridad:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph("Observaciones de seguridad", estilos["TextoNormalEspaciado"]))
            for observacion in resultado.observaciones_seguridad:
                elementos.append(Paragraph(f"• {observacion}", estilos["TextoNormalEspaciado"]))

        if resultado.error:
            elementos.append(Spacer(1, 0.2 * cm))
            elementos.append(Paragraph(f"<b>Detalle técnico:</b> {resultado.error}", estilos["TextoNormalEspaciado"]))

        if indice != len(resultados):
            elementos.append(PageBreak())

    documento.build(elementos)
    return ruta_destino
