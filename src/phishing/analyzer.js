import { phishingRules } from "./rules";
import { analyzeUrls } from "./urlAnalyzer";
import { analyzeLinks } from "./linkAnalyzer";
import { analyzeSender } from "./senderAnalyzer";
import { analyzeAttachments } from "./attachmentAnalyzer";
import { combineDetections } from "./riskEngine";

function extractTextFromHtml(html) {
    const content = String(html || "");

    if (!content) {
        return "";
    }

    if (typeof DOMParser !== "undefined") {
        try {
            const parser = new DOMParser();
            const document = parser.parseFromString(content, "text/html");
            return (document.body?.textContent || "")
                .replace(/\s+/g, " ")
                .trim();
        }
        catch (error) {
            // Fall back below intentionally.
        }
    }

    return content
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/\s+/g, " ")
        .trim();
}

export function analyzeEmail(subject, sender, body, attachments) {
    const bodyText = extractTextFromHtml(body);
    const text = `${subject || ""} ${sender || ""} ${bodyText || ""}`.toLowerCase();

    const urlAnalysis = analyzeUrls(text);
    const linkAnalysis = analyzeLinks(body);
    const senderAnalysis = analyzeSender(sender, subject, bodyText);
    const attachmentAnalysis = analyzeAttachments(attachments);

    const contentDetections = [];

    for (const rule of phishingRules) {
        const matched = rule.patterns.some((pattern) => pattern.test(text));

        if (matched) {
            contentDetections.push({
                type: rule.name,
                name: rule.name,
                category: rule.category || "content",
                score: rule.score,
                severity: rule.severity,
                details: rule.name
            });
        }
    }

    const aggregated = combineDetections([
        { category: "content", detections: contentDetections },
        urlAnalysis,
        linkAnalysis,
        senderAnalysis,
        attachmentAnalysis
    ]);

    return {
        score: Math.min(aggregated.score, 100),
        risk: aggregated.risk,
        detections: aggregated.detections.map((detection) => ({
            name: detection.name || detection.type,
            score: detection.score,
            severity: detection.severity,
            ...(detection.url ? { url: detection.url } : {}),
            ...(detection.details ? { details: detection.details } : {})
        }))
    };
}