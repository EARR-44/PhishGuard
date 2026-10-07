const dangerousExtensions = [
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".hta",
    ".iso",
    ".img",
    ".lnk"
];

const suspiciousExtensions = [
    ".docm",
    ".xlsm",
    ".pptm",
    ".zip",
    ".rar",
    ".7z"
];

export function analyzeAttachments(attachments) {

    const detections = [];
    let score = 0;

    if (!attachments || attachments.length === 0) {
        return {
            score: 0,
            detections: []
        };
    }

    for (const attachment of attachments) {

        const name = attachment.name || "";
        const lowerName = name.toLowerCase();

        const dangerous = dangerousExtensions.some(
            extension => lowerName.endsWith(extension)
        );

        const suspicious = suspiciousExtensions.some(
            extension => lowerName.endsWith(extension)
        );

        if (dangerous) {

            detections.push({
                type: "Archivo adjunto potencialmente peligroso",
                score: 30,
                details: name
            });

            score += 30;

        }
        else if (suspicious) {

            detections.push({
                type: "Archivo adjunto que requiere precaución",
                score: 15,
                details: name
            });

            score += 15;
        }
    }

    return {
        score: Math.min(score, 40),
        detections
    };
}