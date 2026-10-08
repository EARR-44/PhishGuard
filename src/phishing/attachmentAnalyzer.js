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
    ".lnk",
    ".msi",
    ".com",
    ".cpl",
    ".reg",
    ".url",
    ".chm"
];

const suspiciousExtensions = [
    ".docm",
    ".xlsm",
    ".pptm",
    ".zip",
    ".rar",
    ".7z"
];

function hasDoubleExtension(name) {
    const lowerName = String(name || "").toLowerCase();
    const extensionMatches = [
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
        ".lnk",
        ".msi",
        ".com",
        ".cpl",
        ".reg",
        ".url",
        ".chm",
        ".docm",
        ".xlsm",
        ".pptm",
        ".zip",
        ".rar",
        ".7z"
    ];

    const baseName = lowerName.split(".").slice(0, -1).join(".");
    return extensionMatches.some((extension) => baseName.includes(extension));
}

export function analyzeAttachments(attachments) {
    const detections = [];
    let score = 0;

    if (!attachments || attachments.length === 0) {
        return {
            category: "attachment",
            score: 0,
            detections: []
        };
    }

    for (const attachment of attachments) {
        const name = attachment.name || "";
        const lowerName = name.toLowerCase();
        const dangerous = dangerousExtensions.some((extension) => lowerName.endsWith(extension));
        const suspicious = suspiciousExtensions.some((extension) => lowerName.endsWith(extension));

        if (dangerous || hasDoubleExtension(lowerName)) {
            detections.push({
                type: "Archivo adjunto potencialmente peligroso",
                category: "attachment",
                score: 30,
                details: name,
                severity: "alta"
            });
            score += 30;
        }
        else if (suspicious) {
            detections.push({
                type: "Archivo adjunto que requiere precaución",
                category: "attachment",
                score: 15,
                details: name,
                severity: "media"
            });
            score += 15;
        }
    }

    return {
        category: "attachment",
        score: Math.min(score, 40),
        detections
    };
}