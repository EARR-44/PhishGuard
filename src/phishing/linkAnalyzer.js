export function analyzeLinks(html) {

    const detections = [];
    let score = 0;

    // Crear un documento temporal para analizar el HTML
    const parser = new DOMParser();
    const document = parser.parseFromString(html, "text/html");

    const links = document.querySelectorAll("a");

    links.forEach(link => {

        const visibleText = (link.textContent || "").trim();
        const href = link.getAttribute("href");

        if (!href) {
            return;
        }

        try {

            const destination = new URL(href, window.location.href);

            const destinationHost = destination.hostname.toLowerCase();

            // Buscar URLs escritas como texto
            const visibleUrlMatch = visibleText.match(
                /https?:\/\/[^\s<>"']+/i
            );

            if (visibleUrlMatch) {

                const visibleUrl = visibleUrlMatch[0];

                const visibleDestination = new URL(visibleUrl);

                const visibleHost =
                    visibleDestination.hostname.toLowerCase();

                // Comparar dominio visible contra dominio real
                if (visibleHost !== destinationHost) {

                    detections.push({
                        type: "Enlace engañoso",
                        url: href,
                        score: 35,
                        details:
                            `El enlace muestra ${visibleHost} pero dirige a ${destinationHost}`
                    });

                    score += 35;
                }
            }

        } catch (error) {

            // Ignorar enlaces que no sean URLs válidas
        }

    });

    return {
        score: Math.min(score, 50),
        detections
    };
}