import { phishingRules } from "./rules";
import { analyzeUrls } from "./urlAnalyzer";
import { analyzeLinks } from "./linkAnalyzer";
import { analyzeSender } from "./senderAnalyzer";
import { analyzeAttachments } from "./attachmentAnalyzer";

export function analyzeEmail(subject, sender, body, attachments) {

    const text = `
        ${subject}
        ${sender}
        ${body}
    `.toLowerCase();

// Analizar URLs
const urlAnalysis = analyzeUrls(text);

// Analizar enlaces HTML
const linkAnalysis = analyzeLinks(body);

const senderAnalysis = analyzeSender(
    sender,
    subject,
    body
);

const attachmentAnalysis = analyzeAttachments(
    attachments
);

let score = 0;
const detections = [];

// Analizar reglas de phishing
for (const rule of phishingRules) {

    let detected = false;

    for (const pattern of rule.patterns) {

        if (pattern.test(text)) {
            detected = true;
            break;
        }

    }

    if (detected) {

        score += rule.score;

        detections.push({
            name: rule.name,
            score: rule.score,
            severity: rule.severity
        });
    }
}

// Agregar análisis de URLs
score += urlAnalysis.score;

detections.push(
    ...urlAnalysis.detections.map(detection => ({
        name: detection.type,
        score: detection.score,
        severity: detection.score >= 20 ? "alta" : "media",
        url: detection.url
    }))
);

// Agregar análisis de enlaces engañosos
score += linkAnalysis.score;

detections.push(
    ...linkAnalysis.detections.map(detection => ({
        name: detection.type,
        score: detection.score,
        severity: "alta",
        url: detection.url,
        details: detection.details
    }))
);

score += senderAnalysis.score;
detections.push(
    ...senderAnalysis.detections.map(detection => ({
        name: detection.type,
        score: detection.score,
        severity: detection.score >= 20 ? "alta" : "media",
        details: detection.details
    }))
);

score += attachmentAnalysis.score;
detections.push(
    ...attachmentAnalysis.detections.map(detection => ({
        name: detection.type,
        score: detection.score,
        severity: detection.score >= 20 ? "alta" : "media",
        details: detection.details
    }))
);

    // Limitar puntuación máxima a 100
    score = Math.min(score, 100);

    let risk;

    if (score >= 70) {
        risk = "CRÍTICO";
    }
    else if (score >= 50) {
        risk = "ALTO";
    }
    else if (score >= 30) {
        risk = "MEDIO";
    }
    else {
        risk = "BAJO";
    }

    const detectionGroups = new Map();

    for (const detection of detections) {
        let group = detectionGroups.get(detection.name);

        if (!group) {
            group = {
                name: detection.name,
                score: 0,
                severity: detection.severity,
                urls: [],
                details: []
            };
            detectionGroups.set(detection.name, group);
        }

        group.score += detection.score;

        if (detection.severity === "alta") {
            group.severity = "alta";
        }

        const urls = detection.urls || (detection.url ? [detection.url] : []);
        for (const url of urls) {
            if (!group.urls.includes(url)) {
                group.urls.push(url);
            }
        }

        if (detection.details && !group.details.includes(detection.details)) {
            group.details.push(detection.details);
        }
    }

    const groupedDetections = Array.from(detectionGroups.values(), group => {
        const details = [...group.details];

        if (group.urls.length > 0) {
            details.push(`URLs: ${group.urls.join(", ")}`);
        }

        return {
            name: group.name,
            score: group.score,
            severity: group.severity,
            ...(group.urls.length > 0 ? { url: group.urls[0], urls: group.urls } : {}),
            ...(details.length > 0 ? { details: details.join("\n") } : {})
        };
    });

    return {
        score,
        risk,
        detections: groupedDetections
    };
}