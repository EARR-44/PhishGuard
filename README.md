# PhishGuard

**Analizador de correos sospechosos para Outlook.**

PhishGuard es un complemento de Outlook que ayuda a identificar señales comunes de phishing en un correo. Analiza el mensaje seleccionado y presenta un nivel de riesgo, una puntuación y los indicadores encontrados para apoyar su revisión.

> PhishGuard entrega señales para ayudar a evaluar un correo; no confirma por sí solo que un mensaje sea seguro o malicioso. Revisa los resultados antes de tomar medidas.

## ¿Qué hace?

Al pulsar **Analizar correo**, PhishGuard revisa:

- **El texto del mensaje:** busca solicitudes de contraseñas o credenciales, urgencia, amenazas y solicitudes de verificación.
- **Las direcciones web:** detecta enlaces acortados, direcciones HTTP sin cifrado, dominios con extensiones consideradas sospechosas y URLs con formato no válido.
- **Los enlaces del mensaje:** comprueba si una dirección visible en el texto apunta a un dominio distinto del destino real.
- **El remitente:** revisa formatos y dominios asociados a cuentas temporales o palabras que pueden resultar sospechosas.
- **Los adjuntos:** identifica extensiones potencialmente peligrosas o que requieren precaución.

El resultado incluye una puntuación de **0 a 100**, una categoría de riesgo y una lista de indicadores. Las señales del mismo tipo se agrupan para que no aparezcan repetidas; cuando corresponde, se conservan los enlaces asociados y se suman sus puntuaciones.

### Categorías de riesgo

| Puntuación | Nivel |
| --- | --- |
| 0–29 | Bajo |
| 30–49 | Medio |
| 50–69 | Alto |
| 70–100 | Crítico |

Los umbrales son reglas heurísticas del proyecto y pueden cambiar a medida que evolucione el analizador.

## Reportar un posible phishing

Cuando la puntuación alcanza el umbral configurado, aparece **Reportar phishing**. Al confirmar, PhishGuard prepara un borrador de Outlook dirigido a `erobles@financiacapital.cl` con:

- El remitente y el asunto originales.
- La fecha de generación del reporte.
- El nivel y la puntuación de riesgo.
- Los indicadores detectados, sus puntuaciones y los detalles o URLs disponibles.

El borrador **no se envía automáticamente**: la persona debe revisarlo y pulsar **Enviar** en Outlook. El identificador `PG-AAAA-NNNNN` se genera localmente y su secuencia dura solo mientras la instancia del complemento permanece abierta.

## Requisitos

- Node.js y npm.
- Outlook compatible con complementos de Office.
- Una cuenta de Outlook para probar el complemento.

## Ejecutar en desarrollo

1. Clona el repositorio y entra en la carpeta del proyecto:

   ```bash
   git clone https://github.com/EARR-44/PhishGuard.git
   cd PhishGuard
   ```

2. Instala las dependencias:

   ```bash
   npm install
   ```

3. Inicia el complemento en Outlook:

   ```bash
   npm run start
   ```

   El comando utiliza `manifest.xml` para iniciar el servidor de desarrollo HTTPS y cargar el complemento. Si el entorno solicita instalar o confiar en un certificado de desarrollo, sigue las indicaciones de Office Add-in Dev Settings.

4. Abre un mensaje en Outlook, abre el panel de **PhishGuard** y pulsa **Analizar correo**.

Para detener la sesión de desarrollo:

```bash
npm run stop
```

## Comandos disponibles

| Comando | Descripción |
| --- | --- |
| `npm run start` | Inicia la depuración y carga el complemento usando el manifiesto. |
| `npm run stop` | Detiene la sesión de depuración del complemento. |
| `npm run build` | Genera la compilación de producción en `dist/`. |
| `npm run build:dev` | Genera una compilación de desarrollo. |
| `npm run dev-server` | Inicia el servidor de desarrollo de webpack. |
| `npm run validate` | Valida la estructura de `manifest.xml`. |
| `npm run lint` | Ejecuta las comprobaciones de lint configuradas. |

## Estructura del proyecto

```text
src/
├── commands/       # Comandos de Office.
├── phishing/       # Reglas y analizadores de correo, remitente, URLs y adjuntos.
└── taskpane/       # Interfaz de Outlook y flujo de reporte.
assets/             # Iconos del complemento.
manifest.xml        # Configuración y puntos de entrada del add-in.
webpack.config.js   # Configuración de compilación y servidor local.
```

## Cómo funciona el análisis

El análisis se ejecuta en el complemento y combina reglas y resultados de analizadores especializados. Cada indicador aporta puntos, la puntuación total se limita a 100 y se asigna la categoría de riesgo correspondiente. No se consultan servicios externos de reputación ni se contacta un servidor de reportes.

Al preparar un reporte, se abre un borrador mediante Outlook. Los datos solo se envían al destinatario cuando la persona decide pulsar **Enviar**.

## Importante para publicar

La configuración actual de `manifest.xml` apunta a `https://localhost:3000`, que es una dirección local de desarrollo. Antes de distribuir o publicar el complemento, hay que alojar la aplicación y sus recursos en un servidor HTTPS accesible por los usuarios y actualizar las URLs del manifiesto.

## Tecnologías

- JavaScript
- Office.js
- Webpack
- Complementos de Outlook
