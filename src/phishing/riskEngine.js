import { normalizeUrl } from "./urlNormalizer";

const CATEGORY_LIMITS = {
    content: 35,
    url: 30,
    link: 30,
    sender: 20,
    attachment: 25,
};

function getRisk(score) {
    if (score >= 70) {
        return "CRÍTICO";
    }

    if (score >= 50) {
        return "ALTO";
    }

    if (score >= 30) {
        return "MEDIO";
    }

    return "BAJO";
}

function normalizeDetection(detection, fallbackCategory = "content") {
    const rawType = detection?.type || detection?.name || "Indicador sospechoso";
    const category = detection?.category || fallbackCategory;
    const score = Number(detection?.score ?? 0) || 0;

    return {
        ...detection,
        type: rawType,
        name: detection?.name || rawType,
        category,
        score,
        severity: detection?.severity || (score >= 20 ? "alta" : "media"),
        url: detection?.url ? normalizeUrl(detection.url) : detection?.url || undefined,
        details: detection?.details || "",
    };
}

function toKey(detection) {
    const typeKey = (detection.type || detection.name || "indicator").toLowerCase();
    const urlKey = detection.url ? normalizeUrl(detection.url) : "";
    const detailsKey = (detection.details || "").toLowerCase();

    return `${detection.category || "content"}|${typeKey}|${urlKey}|${detailsKey}`;
}

export function combineDetections(analysisItems = []) {
    const merged = new Map();
    const categoryTotals = {
        content: 0,
        url: 0,
        link: 0,
        sender: 0,
        attachment: 0,
    };

    for (const analysisItem of analysisItems) {
        const detections = Array.isArray(analysisItem?.detections) ? analysisItem.detections : [];

        for (const detection of detections) {
            const normalized = normalizeDetection(detection, analysisItem?.category || "content");
            const key = toKey(normalized);

            if (!merged.has(key)) {
                merged.set(key, { ...normalized, originalScore: normalized.score });
                continue;
            }

            const existing = merged.get(key);
            existing.originalScore = Math.max(existing.originalScore, normalized.score);
            existing.score = Math.max(existing.score, normalized.score);

            if (existing.details && normalized.details && !existing.details.includes(normalized.details)) {
                existing.details = `${existing.details}; ${normalized.details}`;
            }
        }
    }

    const detections = [];
    let total = 0;

    for (const detection of merged.values()) {
        const category = detection.category || "content";
        const limit = CATEGORY_LIMITS[category] ?? 35;
        const remaining = Math.max(0, limit - categoryTotals[category]);
        const contribution = Math.min(detection.originalScore || detection.score || 0, remaining);

        categoryTotals[category] += contribution;
        total += contribution;

        detections.push({
            ...detection,
            score: contribution,
            severity: detection.severity || (contribution >= 20 ? "alta" : "media"),
        });
    }

    const score = Math.min(total, 100);

    return {
        score,
        risk: getRisk(score),
        detections: detections
            .sort((a, b) => (b.score || 0) - (a.score || 0))
            .map((detection) => ({
                name: detection.name || detection.type,
                type: detection.type,
                category: detection.category,
                score: detection.score,
                severity: detection.severity,
                ...(detection.url ? { url: detection.url } : {}),
                ...(detection.details ? { details: detection.details } : {}),
            })),
    };
}
