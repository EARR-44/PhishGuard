export function analyzeSender(sender, subject, body) {

    const detections = [];
    let score = 0;

    if (!sender) {
        return {
            score: 0,
            detections: []
        };
    }

    const email = sender.toLowerCase().trim();

    // Extraer dominio del correo
    const parts = email.split("@");

    if (parts.length !== 2) {
        return {
            score: 15,
            detections: [
                {
                    type: "Remitente con formato sospechoso",
                    score: 15,
                    details: email
                }
            ]
        };
    }

    const domain = parts[1];

    /*
     * Dominios frecuentemente utilizados para cuentas
     * temporales o sospechosas.
     */
    const suspiciousDomains = [
        "mailinator.com",
        "tempmail.com",
        "10minutemail.com",
        "guerrillamail.com"
    ];

    if (suspiciousDomains.includes(domain)) {

        detections.push({
            type: "Remitente de dominio temporal",
            score: 25,
            details: domain
        });

        score += 25;
    }

    /*
     * Detectar dominios que contienen palabras relacionadas
     * con seguridad, soporte, login, etc.
     */
    const suspiciousWords = [
        "secure",
        "security",
        "verify",
        "verification",
        "login",
        "support",
        "account",
        "update"
    ];

    for (const word of suspiciousWords) {

        if (domain.includes(word)) {

            detections.push({
                type: "Dominio del remitente potencialmente sospechoso",
                score: 15,
                details: domain
            });

            score += 15;

            break;
        }
    }

    return {
        score: Math.min(score, 30),
        detections
    };
}