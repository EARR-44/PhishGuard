import { normalizeHostname, normalizeUrl } from "./urlNormalizer";

export function analyzeLinks(html) {
    const detections = [];
    let score = 0;

    if (!html) {
        return {
            category: "link",
            score: 0,
            detections: []
        };
    }

    const parser = typeof DOMParser !== "undefined" ? new DOMParser() : null;
    const document = parser ? parser.parseFromString(html, "text/html") : null;
    const links = document ? document.querySelectorAll("a") : [];

    for (const link of links) {
        const href = link.getAttribute("href");

        if (!href) {
            continue;
        }

        const visibleText = (link.textContent || "").trim();

        try {
            const destination = new URL(href, "https://example.com/");
            const destinationHost = normalizeHostname(destination.hostname);

            if (!visibleText) {
                continue;
            }

            const visibleUrlMatch = visibleText.match(/https?:\/\/[^\s<>"']+/i);
            if (!visibleUrlMatch) {
                continue;
            }

            const visibleUrl = visibleUrlMatch[0];
            const visibleDestination = new URL(visibleUrl);
            const visibleHost = normalizeHostname(visibleDestination.hostname);

            if (visibleHost === destinationHost || visibleHost === `www.${destinationHost}` || `www.${visibleHost}` === destinationHost) {
                continue;
            }

            const detectionScore = 35;
            detections.push({
                type: "Enlace engañoso",
                category: "link",
                url: normalizeUrl(href) || href,
                score: detectionScore,
                details: `El enlace muestra ${visibleHost} pero dirige a ${destinationHost}`,
                severity: "alta"
            });

            score += detectionScore;
        }
        catch (error) {
            continue;
        }
    }

    return {
        category: "link",
        score: Math.min(score, 50),
        detections
    };
}