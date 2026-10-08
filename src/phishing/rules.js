export const phishingRules = [
    {
        name: "Solicitud de contraseña",
        category: "content",
        patterns: [
            /ingrese\s+(su\s+)?contraseña/i,
            /introduzca\s+(su\s+)?contraseña/i,
            /proporcione\s+(su\s+)?contraseña/i,
            /confirme\s+(su\s+)?contraseña/i,
            /verifique\s+(su\s+)?contraseña/i
        ],
        score: 30,
        severity: "alta"
    },
    {
        name: "Cuenta bloqueada o suspendida",
        category: "content",
        patterns: [
            /cuenta\s+(será\s+)?bloqueada/i,
            /cuenta\s+suspendida/i,
            /cuenta\s+será\s+suspendida/i,
            /acceso\s+será\s+bloqueado/i
        ],
        score: 20,
        severity: "alta"
    },
    {
        name: "Lenguaje de urgencia",
        category: "content",
        patterns: [
            /urgente/i,
            /inmediatamente/i,
            /último\s+aviso/i,
            /acción\s+inmediata/i,
            /actúe\s+ahora/i,
            /de\s+inmediato/i
        ],
        score: 15,
        severity: "media"
    },
    {
        name: "Solicitud de verificación",
        category: "content",
        patterns: [
            /verifique\s+(su\s+)?cuenta/i,
            /confirme\s+(su\s+)?identidad/i,
            /valide\s+(su\s+)?cuenta/i,
            /actualice\s+(sus\s+)?datos/i
        ],
        score: 15,
        severity: "media"
    },
    {
        name: "Solicitud de credenciales",
        category: "content",
        patterns: [
            /nombre\s+de\s+usuario/i,
            /usuario\s+y\s+contraseña/i,
            /credenciales/i,
            /datos\s+de\s+acceso/i
        ],
        score: 25,
        severity: "alta"
    },
    {
        name: "Lenguaje de amenaza",
        category: "content",
        patterns: [
            /perderá\s+el\s+acceso/i,
            /se\s+eliminará\s+su\s+cuenta/i,
            /será\s+eliminado/i,
            /última\s+oportunidad/i
        ],
        score: 20,
        severity: "alta"
    },
    {
        name: "Business Email Compromise",
        category: "content",
        patterns: [
            /(transferencia|pago|factura|cuenta bancaria).*(urgente|inmediato|hoy|ahora)/i,
            /(cambio de cuenta bancaria|nueva cuenta bancaria|modificación de datos bancarios|datos bancarios).*(pago|transferencia|factura|urgente)/i,
            /(no llamar|no responder|fuera de la oficina|confidencial).*(transferencia|cuenta|pago|factura)/i,
            /(tarjetas de regalo|gift cards|gift card).*(urgente|inmediato|pago|entrega)/i,
            /(transferencia urgente|pago inmediato|factura modificada|datos bancarios confidenciales)/i
        ],
        score: 35,
        severity: "alta"
    }
];