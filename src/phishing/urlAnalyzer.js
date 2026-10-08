import { normalizeHostname, normalizeUrl, normalizeComparisonKey } from "./urlNormalizer";

const shortenedDomains = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly"
];

const suspiciousExtensions = [
    ".xyz",
    ".top",
    ".click",
    ".live",
    ".work",
    ".zip",
    ".mov"
];

export function extractUrls(text) {
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    const matches = text.match(urlRegex) || [];

    return matches
        .map((url) => url.replace(/&amp;/gi, "&").replace(/[),.;]+$/, ""))
        .filter(Boolean);
}

export function analyzeUrls(text) {
    const urls = [...new Set(extractUrls(String(text || "")))];
    const detections = [];
    const detectedKeys = new Set();
    let score = 0;

    function addDetection(type, url, detectionScore, details = "") {
        const normalizedUrl = normalizeUrl(url) || url;
        const key = `${type}|${normalizeComparisonKey(type, normalizedUrl)}`;

        if (detectedKeys.has(key)) {
            return;
        }

        detectedKeys.add(key);
        detections.push({
            type,
            category: "url",
            url: normalizedUrl,
            score: detectionScore,
            details,
            severity: detectionScore >= 20 ? "alta" : "media"
        });

        score += detectionScore;
    }

    for (const rawUrl of urls) {
        const url = normalizeUrl(rawUrl) || rawUrl;

        try {
            const parsedUrl = new URL(url);
            const hostname = normalizeHostname(parsedUrl.hostname);

            if (shortenedDomains.includes(hostname)) {
                addDetection("URL acortada", url, 15, `Dominio acortado: ${hostname}`);
            }

            if (hostname.includes("xn--") || hostname.includes("%2e")) {
                addDetection("Dominio sospechoso por punycode", url, 15, `Hostname con codificación sospechosa: ${hostname}`);
            }

            if (parsedUrl.hostname.match(/\d+\.\d+\.\d+\.\d+/)) {
                addDetection("URL con dirección IP como hostname", url, 20, `El hostname resuelve a una IP: ${parsedUrl.hostname}`);
            }

            if (parsedUrl.port && !["80", "443"].includes(parsedUrl.port)) {
                addDetection("Puerto no estándar", url, 10, `El puerto ${parsedUrl.port} no es el predeterminado para la URL.`);
            }

            const labels = hostname.split(".").filter(Boolean);
            if (labels.length > 4) {
                addDetection("Hostname con demasiados subdominios", url, 12, `El dominio tiene demasiados niveles: ${hostname}`);
            }

            if (parsedUrl.username || parsedUrl.password) {
                addDetection("URL con credenciales embebidas", url, 12, "La URL incluye usuario y/o contraseña dentro del hostname.");
            }

            if (parsedUrl.protocol === "http:") {
                addDetection("Conexión HTTP sin cifrado", url, 10, "La URL usa HTTP, sin cifrado TLS.");
            }

            const hasSuspiciousExtension = suspiciousExtensions.some((extension) => hostname.endsWith(extension));
            if (hasSuspiciousExtension) {
                addDetection("Dominio potencialmente sospechoso", url, 20, `El dominio termina en una extensión sospechosa: ${hostname}`);
            }

            if (hostname.includes("login") || hostname.includes("verify") || hostname.includes("security") || hostname.includes("account")) {
                addDetection("Dominio sospechoso por estructura", url, 12, `El dominio contiene tokens típicos de phishing: ${hostname}`);
            }

            if (hostname.includes("xn--")) {
                addDetection("URL con punycode", url, 15, `El dominio usa punycode: ${hostname}`);
            }
        }
        catch (error) {
            addDetection("URL con formato sospechoso", url, 15, `La URL no pudo ser parseada: ${rawUrl}`);
        }
    }

    return {
        category: "url",
        urls: [...new Set(urls.map((item) => normalizeUrl(item) || item))],
        score: Math.min(score, 50),
        detections
    };
}