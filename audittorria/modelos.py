from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class ResultadoPuerto:
    """Representa el estado de un puerto concreto durante la auditoría."""

    numero: int
    servicio: str
    estado: str


@dataclass
class ResultadoEquipo:
    """Agrupa la información recopilada para un equipo de la red."""

    ip: str
    activo: bool = False
    tiempo_respuesta_ms: str = "No disponible"
    categoria_latencia: str = "No disponible"
    ttl: str = "No disponible"
    sistema_operativo_probable: str = "No determinado"
    nombre_host: str = "No resuelto"
    puertos_abiertos: list[ResultadoPuerto] = field(default_factory=list)
    comprobaciones_adicionales: list[str] = field(default_factory=list)
    versiones_servicios: list[str] = field(default_factory=list)
    vulnerabilidades_cve: list[str] = field(default_factory=list)
    informacion_sistema: list[str] = field(default_factory=list)
    hallazgos_host: list[str] = field(default_factory=list)
    observaciones_seguridad: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class ParametrosAuditoria:
    """Centraliza todos los parámetros necesarios para ejecutar una auditoría."""

    objetivos: list[str]
    descripcion_objetivo: str
    puertos: list[int]
    ruta_pdf: Path
    concurrencia: int = 32
    modo_auditoria: str = "red"


@dataclass
class ResumenAuditoria:
    """Empaqueta los resultados y la ubicación del informe final para reutilizarlos."""

    parametros: ParametrosAuditoria
    resultados: list[ResultadoEquipo]


@dataclass
class ProgresoAuditoria:
    """Representa el avance actual de una auditoría para informar a consola o GUI."""

    completados: int
    total: int
    porcentaje: float
    mensaje: str
    resultado_equipo: ResultadoEquipo | None = None


# Alias para simplificar el tipado de funciones que reciben mensajes de progreso.
NotificadorProgreso = Callable[[ProgresoAuditoria], None]
