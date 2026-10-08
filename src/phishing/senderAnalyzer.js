export function analyzeSender(sender, subject, body) {
    const detections = [];
    let score = 0;

    if (!sender) {
        return {
            category: "sender",
            score: 0,
            detections: []
        };
    }

    const email = sender.toLowerCase().trim();
    const parts = email.split("@");

    if (parts.length !== 2) {
        return {
            category: "sender",
            score: 15,
            detections: [{
                type: "Remitente con formato sospechoso",
                category: "sender",
                score: 15,
                details: email,
                severity: "media"
            }]
        };
    }

    const domain = parts[1];
    const suspiciousDomains = [
        "mailinator.com",
        "tempmail.com",
        "10minutemail.com",
        "guerrillamail.com"
    ];

    if (suspiciousDomains.includes(domain)) {
        detections.push({
            type: "Remitente de dominio temporal",
            category: "sender",
            score: 25,
            details: domain,
            severity: "alta"
        });
        score += 25;
    }

    const combinedText = `${subject || ""} ${body || ""}`.toLowerCase();
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

    const suspiciousWordMatches = suspiciousWords.filter((word) => domain.includes(word));
    if (suspiciousWordMatches.length > 0 && /credential|password|contraseña|verifique|actualice|cuenta|seguridad/i.test(combinedText)) {
        detections.push({
            type: "Dominio del remitente potencialmente sospechoso",
            category: "sender",
            score: 15,
            details: domain,
            severity: "media"
        });
        score += 15;
    }

    return {
        category: "sender",
        score: Math.min(score, 30),
        detections
    };
}