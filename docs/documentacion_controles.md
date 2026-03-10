# Documentación de controles de AudiTorría

## Visión general

AudiTorría es un programa de revisión de seguridad y red creado para las prácticas en ACEIMAR.
Sirve para comprobar equipos de una red, direcciones IP concretas o el propio ordenador en el que se ejecuta.
Los resultados se muestran en la pantalla y también pueden guardarse en un archivo PDF.
Además, la aplicación incluye una ventana de ayuda con pestañas y buscador.

## Modos de uso

- Red: revisa los equipos de una red indicada por el usuario.
- IPs concretas: revisa solo las direcciones indicadas manualmente.
- Equipo local: revisa el propio ordenador donde se está ejecutando el programa.

En el modo Red se puede escribir la red completa con máscara, por ejemplo `192.168.1.0/24`.
También se puede escribir solo una IP base como `192.168.1.0` y AudiTorría la interpretará como `192.168.1.0/24`.

## Qué comprueba por red

- Si un equipo responde por red.
- Cuánto tarda en responder.
- Qué nombre parece tener ese equipo.
- Qué puertos abiertos tiene dentro de la lista revisada.
- Qué tipo de servicio parece haber detrás de cada puerto abierto.
- Qué información visible devuelve el servicio al conectarse.
- Si un servicio web responde y qué datos muestra.
- Si es posible adivinar la versión de algunos servicios.
- Si esa versión puede estar relacionada con fallos de seguridad conocidos.

## Cómo intenta reconocer versiones por red

Cuando AudiTorría se conecta a un servicio, a veces ese servicio devuelve una pequeña respuesta visible.
Esa respuesta puede incluir el nombre del programa o su versión.

Ejemplos habituales:

- un servicio SSH puede decir qué programa está usando
- un servicio web puede mostrar el nombre y versión del servidor
- un servicio de correo o transferencia de archivos puede mostrar un mensaje inicial identificativo

Con esa información, AudiTorría intenta saber:

- qué programa hay detrás del servicio
- qué versión parece estar expuesta
- si esa versión tiene fallos de seguridad conocidos publicados

Esta parte es orientativa, porque algunos servicios ocultan esa información o muestran datos incompletos.

## Qué comprueba en el equipo local

- direcciones IP del equipo
- puertos abiertos en el propio ordenador
- estado del cortafuegos
- estado general de actualizaciones
- reglas básicas de contraseñas
- usuarios y permisos relevantes
- servicios activos
- tareas programadas
- carpetas o recursos compartidos
- ajustes generales de seguridad del sistema
- versiones realmente instaladas de algunos programas importantes
- relación entre esas versiones y fallos de seguridad conocidos

## Detección de versiones en el equipo local

En el modo local, AudiTorría intenta obtener la versión real instalada de algunos programas habituales.
Esto suele ser más fiable que la revisión por red.

Por ejemplo, puede intentar revisar programas como:

- servidor web
- servidor SSH
- base de datos
- servidor de impresión
- servidor de archivos

Si consigue una versión clara, intenta compararla con una base pública de fallos de seguridad conocidos.

## Controles de Linux

En Linux, el programa puede revisar, entre otras cosas:

- estado del cortafuegos
- tareas automáticas del sistema
- carpetas compartidas más comunes
- ajustes generales de protección del sistema
- permisos de carpetas delicadas como `.ssh`
- versiones instaladas de algunos programas comunes, cuando el sistema las permite consultar

## Controles de Windows

En Windows, el programa puede revisar, entre otras cosas:

- protección general del sistema
- cifrado de disco
- configuración del cortafuegos
- actualizaciones y reinicios pendientes
- protección de Microsoft Defender
- acceso remoto
- cuentas locales y grupos con permisos altos
- tareas automáticas y programas que se inician solos
- dispositivos USB
- redes Wi-Fi guardadas
- historial básico de conexiones remotas
- programas antiguos o de riesgo
- programas de acceso remoto de terceros
- versiones de algunos servicios instalados en el equipo

... las revisiones de Windows todavía está por probar ... ya que yo no tengo Windows.

## Navegadores y certificados

AudiTorría también puede revisar información básica de navegadores, por ejemplo:

- perfiles de usuario de Chrome, Edge y Firefox
- extensiones instaladas
- certificados de cliente del sistema usados por algunos navegadores
- datos propios de Firefox relacionados con certificados y módulos de seguridad

## Fallos de seguridad conocidos

Cuando AudiTorría consigue averiguar el nombre de un programa y su versión, intenta buscar si existe información pública sobre fallos de seguridad conocidos.

Esa búsqueda se usa para:

- mostrar posibles problemas relacionados con esa versión
- dar prioridad a los problemas más graves
- incluir esa información tanto en la pantalla como en el PDF

## Presentación de resultados

La aplicación muestra:

- una tabla con los equipos revisados
- filtros para buscar resultados
- una ventana de detalle por equipo
- colores para distinguir mejor el nivel de riesgo
- un informe PDF con resumen y detalle

En el caso del equipo local, el PDF muestra las direcciones IP detectadas en el propio ordenador.

## Limitaciones importantes

- Puede que no todos los equipos o servicios muestran información suficiente.
- Algunas comprobaciones dependen del sistema operativo y de los permisos disponibles.
- Parte de la información es orientativa y conviene revisarla manualmente para estar seguros de lo que el programa ofrece.
- Las coincidencias con fallos de seguridad conocidos no sustituyen una revisión profesional completa.
- Algunas comprobaciones de Windows solo se confirman bien al ejecutar la herramienta directamente en Windows.
