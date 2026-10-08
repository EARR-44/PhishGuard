function decodeHtmlEntities(value) {
    return String(value)
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&#x27;/gi, "'")
        .replace(/&#x2F;/gi, "/")
        .replace(/&sol;/gi, "/");
}

export function normalizeHostname(hostname) {
    if (!hostname) {
        return "";
    }

    let normalized = decodeHtmlEntities(hostname)
        .trim()
        .toLowerCase()
        .replace(/\.+$/, "")
        .replace(/\.$/, "")
        .replace(/^\.+/, "");

    normalized = normalized.replace(/^www\./i, "");

    if (normalized.startsWith("[")) {
        normalized = normalized.replace(/^\[|\]$/g, "");
    }

    return normalized;
}

export function normalizeUrl(url) {
    if (!url) {
        return "";
    }

    let candidate = decodeHtmlEntities(String(url).trim()).replace(/[),.;]+$/, "");

    if (!candidate) {
        return "";
    }

    try {
        let preparedUrl = candidate;

        if (/^\/\//.test(preparedUrl)) {
            preparedUrl = `https:${preparedUrl}`;
        }

        if (!/^https?:\/\//i.test(preparedUrl)) {
            return candidate.toLowerCase();
        }

        const parsed = new URL(preparedUrl);
        const protocol = parsed.protocol.toLowerCase();
        const hostname = normalizeHostname(parsed.hostname);

        if (!hostname) {
            return candidate.toLowerCase();
        }

        const defaultPort = protocol === "http:" ? "80" : protocol === "https:" ? "443" : "";
        const port = parsed.port && parsed.port !== defaultPort ? `:${parsed.port}` : "";

        let pathname = parsed.pathname || "/";

        if (pathname.length > 1 && pathname.endsWith("/")) {
            pathname = pathname.replace(/\/+$/, "");
        }

        const search = parsed.search || "";
        const origin = `${protocol}//${hostname}${port}`;
        const normalized = new URL(`${origin}${pathname}${search}`);
        normalized.hash = "";

        return normalized.toString();
    }
    catch (error) {
        return candidate.replace(/#.*$/, "").toLowerCase();
    }
}

export function normalizeComparisonKey(type, url) {
    if (!type) {
        return "unknown";
    }

    return `${type.toLowerCase()}|${normalizeUrl(url) || String(url || "").trim().toLowerCase()}`;
}
