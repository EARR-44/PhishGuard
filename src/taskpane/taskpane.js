import { analyzeEmail as analyzePhishing } from "../phishing/analyzer";

/* global Office */

const REPORT_RECIPIENT = "soporte.ti@financiacapital.cl";

let lastAnalysis = null;
let lastEmail = null;
let lastResultHtml = null;
let reportSequence = 0;

Office.onReady(() => {

    const analyzeButton = document.getElementById("analyzeButton");
    const reportButton = document.getElementById("reportButton");

    analyzeButton.addEventListener("click", readEmail);

    if (reportButton) {
        reportButton.addEventListener("click", reportPhishing);
    }

});

function readEmail() {

    const item = Office.context.mailbox.item;
    const result = document.getElementById("result");

    result.innerHTML = "<p>🔄 Leyendo correo...</p>";

    // Asunto
    const subject = item.subject || "(Sin asunto)";

    // Adjuntos
    const attachments = item.attachments || [];

    // Remitente
    let sender = "(Desconocido)";

    if (item.from && item.from.emailAddress) {
        sender = item.from.emailAddress;
    }

    // Obtener cuerpo HTML
    item.body.getAsync(
        Office.CoercionType.Html,
        function (asyncResult) {

            if (asyncResult.status === Office.AsyncResultStatus.Succeeded) {

                const body = asyncResult.value;

                // Analizar
                const analysis = analyzePhishing(
                    subject,
                    sender,
                    body,
                    attachments
                );

                // Guardar para reportes
                lastAnalysis = analysis;

                lastEmail = {
                    subject,
                    sender
                };

                // Mostrar botón reportar
                const reportButton =
                    document.getElementById("reportButton");

                if (reportButton) {

                    if (analysis.score >= 30) {
                        reportButton.style.display = "block";
                    }
                    else {
                        reportButton.style.display = "none";
                    }

                }

                // Semáforo
                let riskIcon = "🟢";
                let riskMessage =
                    "No se detectaron indicadores importantes.";

                if (analysis.risk === "MEDIO") {

                    riskIcon = "🟡";

                    riskMessage =
                        "Se detectaron algunos indicadores sospechosos.";

                }
                else if (analysis.risk === "ALTO") {

                    riskIcon = "🟠";

                    riskMessage =
                        "Este correo presenta varios indicadores de phishing.";

                }
                else if (analysis.risk === "CRÍTICO") {

                    riskIcon = "🔴";

                    riskMessage =
                        "No se recomienda interactuar con este correo.";

                }

                // Mostrar resultado
                result.innerHTML = `
                    <h3>🛡️ Resultado del análisis</h3>

                    <h2>
                        ${riskIcon} ${analysis.risk}
                    </h2>

                    <p>
                        ${riskMessage}
                    </p>

                    <p>
                        <strong>Puntuación:</strong>
                        ${analysis.score}/100
                    </p>

                    ${
                        analysis.detections.length > 0
                        ? `
                            <p>
                                <strong>Indicadores detectados:</strong>
                            </p>

                            <ul>
                                ${analysis.detections
                                    .map(detection => `
                                        <li>
                                            <strong>
                                                ${escapeHtml(detection.name)}
                                            </strong>
                                            (+${escapeHtml(detection.score)})

                                            ${
                                                detection.details
                                                ? `
                                                    <br>
                                                    <small class="redacted" tabindex="0" aria-label="Detalle del indicador; enfoque o pase el cursor para revelar">
                                                        ${escapeHtml(detection.details).replace(/\n/g, "<br>")}
                                                    </small>
                                                `
                                                : ""
                                            }
                                        </li>
                                    `)
                                    .join("")}
                            </ul>
                        `
                        : `
                            <p>
                                ✅ No se detectaron indicadores conocidos.
                            </p>
                        `
                    }
                `;

                lastResultHtml = result.innerHTML;

            }
            else {

                result.innerHTML = `
                    <p>❌ No se pudo leer el correo.</p>
                    <p>${asyncResult.error.message}</p>
                `;

            }

        }
    );
}

function reportPhishing() {

    if (!lastAnalysis || !lastEmail) {
        return;
    }

    showReportConfirmation();
}

function showReportConfirmation(errorMessage = "") {

    const result = document.getElementById("result");

    result.innerHTML = `
        <section class="report-confirmation" aria-labelledby="reportConfirmationTitle">
            <h3 id="reportConfirmationTitle">🚨 Reportar phishing</h3>
            ${errorMessage ? '<p class="report-confirmation__error"></p>' : ""}
            <p>¿Deseas reportar este correo al equipo de TI?</p>
            <div class="report-confirmation__actions">
                <button type="button" id="cancelReportButton" class="report-confirmation__cancel">
                    Cancelar
                </button>
                <button type="button" id="confirmReportButton" class="report-confirmation__submit">
                    Reportar
                </button>
            </div>
        </section>
    `;

    if (errorMessage) {
        result.querySelector(".report-confirmation__error").textContent = errorMessage;
    }

    document
        .getElementById("cancelReportButton")
        .addEventListener("click", () => {
            result.innerHTML = lastResultHtml;
        });

    document
        .getElementById("confirmReportButton")
        .addEventListener("click", confirmReport);
}

function confirmReport() {

    const result = document.getElementById("result");
    const reportNumber = String(reportSequence + 1).padStart(5, "0");
    const reportId = `PG-${new Date().getFullYear()}-${reportNumber}`;
    const subject = `PhishGuard | Reporte de phishing | ${reportId}`;
    const detectionsHtml = lastAnalysis.detections.length
        ? lastAnalysis.detections.map(detection => `
            <li>
                <strong>${escapeHtml(detection.name)}</strong>
                (Puntaje: ${escapeHtml(detection.score)}, severidad: ${escapeHtml(detection.severity || "no especificada")})
                ${detection.urls && detection.urls.length
                    ? `<br><strong>URLs:</strong> <code>${escapeHtml(detection.urls.join(", "))}</code>`
                    : detection.url ? `<br><strong>URL:</strong> <code>${escapeHtml(detection.url)}</code>` : ""}
                ${detection.details ? `<br><strong>Detalle:</strong> ${escapeHtml(detection.details)}` : ""}
            </li>
        `).join("")
        : "<li>No se detectaron indicadores específicos.</li>";
    const htmlBody = `
        <div style="font-family:Segoe UI,Arial,sans-serif;color:#17232b;line-height:1.5">
            <h2 style="color:#a61f45">Reporte de posible phishing - PhishGuard</h2>
            <p>Se solicita revisar este correo y evaluar el bloqueo de los indicadores asociados.</p>
            <table style="border-collapse:collapse">
                <tr><td style="padding:4px 12px 4px 0"><strong>ID de reporte</strong></td><td>${escapeHtml(reportId)}</td></tr>
                <tr><td style="padding:4px 12px 4px 0"><strong>Fecha</strong></td><td>${escapeHtml(new Date().toLocaleString("es-CL"))}</td></tr>
                <tr><td style="padding:4px 12px 4px 0"><strong>Riesgo</strong></td><td>${escapeHtml(lastAnalysis.risk)}</td></tr>
                <tr><td style="padding:4px 12px 4px 0"><strong>Puntuación</strong></td><td>${escapeHtml(lastAnalysis.score)}/100</td></tr>
                <tr><td style="padding:4px 12px 4px 0"><strong>Remitente</strong></td><td>${escapeHtml(lastEmail.sender)}</td></tr>
                <tr><td style="padding:4px 12px 4px 0"><strong>Asunto original</strong></td><td>${escapeHtml(lastEmail.subject)}</td></tr>
            </table>
            <h3>Indicadores detectados</h3>
            <ul>${detectionsHtml}</ul>
            <p style="color:#5b6870;font-size:12px">
                Borrador generado por PhishGuard. Revisar los indicadores antes de aplicar bloqueos.
            </p>
        </div>
    `;

    try {
        if (!Office.context.requirements.isSetSupported("Mailbox", "1.6")) {
            throw new Error("Esta versión de Outlook no permite preparar borradores desde PhishGuard. Actualiza Outlook e inténtalo nuevamente.");
        }

        Office.context.mailbox.displayNewMessageForm({
            toRecipients: [REPORT_RECIPIENT],
            subject,
            htmlBody
        });

        reportSequence += 1;
        result.innerHTML = `
            <section class="report-success" role="status" aria-live="polite">
                <h3>✅ Borrador preparado en Outlook</h3>
                <p class="report-success__instruction">Revisa el reporte y pulsa Enviar en Outlook.</p>
                <p>ID del reporte:</p>
                <code class="report-success__id">${escapeHtml(reportId)}</code>
            </section>
        `;

        document.getElementById("reportButton").style.display = "none";
    }
    catch (error) {
        console.error("No se pudo preparar el borrador de reporte en Outlook.", error);
        showReportConfirmation(error.message || "No se pudo abrir el borrador en Outlook. Inténtalo nuevamente.");
    }
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#39;"
    })[character]);
}