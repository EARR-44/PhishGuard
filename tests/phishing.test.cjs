const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const babel = require("@babel/core");

const originalJsExtension = Module._extensions[".js"];
Module._extensions[".js"] = function patchedJs(module, filename) {
    if (filename.includes(`${path.sep}src${path.sep}`) || filename.includes(`${path.sep}tests${path.sep}`)) {
        const source = fs.readFileSync(filename, "utf8");
        const { code } = babel.transformSync(source, {
            filename,
            presets: [["@babel/preset-env", { modules: "commonjs" }]],
            sourceMaps: false,
        });
        module._compile(code, filename);
        return;
    }

    return originalJsExtension(module, filename);
};

const { analyzeEmail } = require("../src/phishing/analyzer.js");
const { analyzeLinks } = require("../src/phishing/linkAnalyzer.js");
const { combineDetections } = require("../src/phishing/riskEngine.js");
const { normalizeUrl } = require("../src/phishing/urlNormalizer.js");

function installDomParserStub() {
    globalThis.DOMParser = class {
        parseFromString(html) {
            const linkMatches = [...String(html).matchAll(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi)];
            const links = linkMatches.map(([, href, content]) => ({
                getAttribute(name) {
                    return name === "href" ? href : null;
                },
                textContent: content.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()
            }));

            return {
                body: { textContent: String(html).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() },
                querySelectorAll(selector) {
                    return selector === "a" ? links : [];
                }
            };
        }
    };
}

test("correo normal no genera riesgo alto", () => {
    const result = analyzeEmail(
        "Reunión semanal",
        "usuario@empresa.cl",
        "Gracias por participar en la reunión del viernes a las 15:00.",
        []
    );

    assert.ok(result.score <= 20, `score inesperado: ${result.score}`);
    assert.equal(result.risk, "BAJO");
});

test("solicitud de contraseña dispara una alerta relevante", () => {
    const result = analyzeEmail(
        "Urgente: confirme su contraseña",
        "soporte@empresa.cl",
        "Ingrese su contraseña para continuar con la validación de su cuenta.",
        []
    );

    assert.ok(result.score >= 30);
    assert.equal(result.risk, "MEDIO");
});

test("cuenta bloqueada se detecta como sospechosa", () => {
    const result = analyzeEmail(
        "Cuenta bloqueada",
        "noreply@falso.cl",
        "Su cuenta será bloqueada si no continúa con la revisión de seguridad.",
        []
    );

    assert.ok(result.score >= 20);
});

test("lenguaje urgente se marca como indicador", () => {
    const result = analyzeEmail(
        "Acción inmediata requerida",
        "alertas@ejemplo.cl",
        "Actúe ahora: esta es una acción inmediata.",
        []
    );

    assert.ok(result.score >= 15);
});

test("URLs con dominio .xyz se detectan", () => {
    const result = analyzeEmail(
        "Verificación",
        "usuario@empresa.cl",
        "https://login-seguridad.xyz/verificar",
        []
    );

    assert.ok(result.detections.some((detection) => /sospechoso|xyz/i.test(detection.name || "")));
});

test("URL HTTP sin cifrado se reporta", () => {
    const result = analyzeEmail(
        "Aviso",
        "usuario@empresa.cl",
        "http://ejemplo.com/confirmar",
        []
    );

    assert.ok(result.detections.some((detection) => /HTTP|cifrado/i.test(detection.name || detection.details || "")));
});

test("URL acortada se detecta", () => {
    const result = analyzeEmail(
        "Atención",
        "usuario@empresa.cl",
        "https://bit.ly/123abc",
        []
    );

    assert.ok(result.detections.some((detection) => /acortada/i.test(detection.name || "")));
});

test("un enlace visible similar al destino real no se marca como engañoso cuando es un caso trivial", () => {
    installDomParserStub();
    const result = analyzeLinks('<a href="https://ejemplo.cl/">https://www.ejemplo.cl</a>');

    assert.equal(result.detections.length, 0);
});

test("un enlace visible diferente del destino real sí se marca", () => {
    installDomParserStub();
    const result = analyzeLinks('<a href="https://bancochile-login.xyz/verify">https://www.bancochile.cl</a>');

    assert.ok(result.detections.some((detection) => /Enlace engañoso/i.test(detection.type || "")));
});

test("archivo .exe genera alerta", () => {
    const result = analyzeEmail(
        "Adjunto importante",
        "usuario@empresa.cl",
        "Revisa el archivo adjunto para confirmar el pago.",
        [{ name: "factura.pdf.exe" }]
    );

    assert.ok(result.detections.some((detection) => /peligroso|adjunto/i.test(detection.name || "")));
});

test("doble extensión se detecta", () => {
    const result = analyzeEmail(
        "Archivo requerido",
        "usuario@empresa.cl",
        "Adjunto urgente.",
        [{ name: "orden.xlsm.exe" }]
    );

    assert.ok(result.score >= 20);
});

test("remitente sospechoso se marca en dominios temporales o raros", () => {
    const result = analyzeEmail(
        "Verificación de cuenta",
        "usuario@mailinator.com",
        "Debe confirmar su cuenta para seguir usando el servicio.",
        []
    );

    assert.ok(result.detections.some((detection) => /temporal|remitente/i.test(detection.name || "")));
});

test("BEC con transferencia urgente y cuenta bancaria se detecta", () => {
    const result = analyzeEmail(
        "Cambio de cuenta bancaria",
        "direccion@empresa.cl",
        "La transferencia urgente requiere cambiar la cuenta bancaria para el pago inmediato.",
        []
    );

    assert.ok(result.detections.some((detection) => /Business Email Compromise|cambio de cuenta|transferencia/i.test(detection.name || detection.details || "")));
});

test("URL duplicada no duplica la detección HTTP", () => {
    const result = combineDetections([
        {
            category: "url",
            detections: [
                { type: "Conexión HTTP sin cifrado", category: "url", score: 10, url: "http://ejemplo.com", details: "Conexión HTTP sin cifrado" },
                { type: "Conexión HTTP sin cifrado", category: "url", score: 10, url: "http://ejemplo.com/", details: "Conexión HTTP sin cifrado" }
            ]
        }
    ]);

    assert.equal(result.detections.filter((d) => /HTTP/i.test(d.name || "")).length, 1);
    assert.ok(result.score <= 10);
});

test("deteciones duplicadas por tipo y url se consolidan", () => {
    const result = combineDetections([
        {
            category: "url",
            detections: [
                { type: "URL acortada", category: "url", score: 15, url: "https://bit.ly/1" },
                { type: "URL acortada", category: "url", score: 15, url: "https://bit.ly/1/" }
            ]
        }
    ]);

    assert.equal(result.detections.filter((d) => /URL acortada/i.test(d.name || "")).length, 1);
});

test("score final no supera 100", () => {
    const result = analyzeEmail(
        "Urgente",
        "usuario@mailinator.com",
        "Ingrese su contraseña en http://malicio.so/verify y revise la cuenta bloqueada. Adjunte factura.pdf.exe.",
        [{ name: "factura.pdf.exe" }]
    );

    assert.ok(result.score <= 100);
    assert.ok(result.risk === "ALTO" || result.risk === "CRÍTICO");
});

test("URL legítima sin falso positivo", () => {
    assert.equal(normalizeUrl("https://www.ejemplo.cl/"), "https://ejemplo.cl/");
    const result = analyzeEmail(
        "Consulta general",
        "contacto@ejemplo.cl",
        "Visite https://www.ejemplo.cl/ para más detalles.",
        []
    );

    assert.ok(result.score < 15);
});
