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

    return matches.map(url =>
        url
            .replace(/&amp;/gi, "&")
            .replace(/[),.;]+$/, "")
    );
}

export function analyzeUrls(text) {

    const urls = extractUrls(text);

    const detections = [];
    const detectedKeys = new Set();

    let score = 0;

    function addDetection(type, url, detectionScore) {

        // Crear identificador único
        const key = `${type}|${url.toLowerCase()}`;

        // Si ya existe, no volver a agregarlo
        if (detectedKeys.has(key)) {
            return;
        }

        detectedKeys.add(key);

        detections.push({
            type,
            url,
            score: detectionScore
        });

        score += detectionScore;
    }

    for (const url of urls) {

        try {

            const parsedUrl = new URL(url);

            const hostname =
                parsedUrl.hostname.toLowerCase();

            // URL acortada
            if (shortenedDomains.includes(hostname)) {

                addDetection(
                    "URL acortada",
                    url,
                    15
                );
            }

            // Extensiones sospechosas
            for (const extension of suspiciousExtensions) {

                if (hostname.endsWith(extension)) {

                    addDetection(
                        "Dominio potencialmente sospechoso",
                        url,
                        20
                    );

                    break;
                }
            }

            // HTTP sin cifrado
            if (parsedUrl.protocol === "http:") {

                addDetection(
                    "Conexión HTTP sin cifrado",
                    url,
                    10
                );
            }

        }
        catch (error) {

            addDetection(
                "URL con formato sospechoso",
                url,
                15
            );
        }
    }

    return {
        urls: [...new Set(urls)],
        score: Math.min(score, 50),
        detections
    };
}