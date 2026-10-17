/**
 * Aviso diario por correo de licencias próximas a vencer (Inventario APP).
 *
 * Es el archivo index.js de una Cloud Function de Firebase (2.ª generación).
 * NO se ejecuta en GitHub Pages: hay que desplegarlo una vez en Firebase.
 *
 * Qué hace: cada día a las 7:00 (hora de Bogotá) lee la colección "licenciamiento" y,
 * por cada licencia a la que le falten 30 días o menos (o ya vencida) y que NO esté
 * marcada como renovada, envía un correo a yoes934@gmail.com desde soporte@app.gov.co
 * (Microsoft 365). Al pulsar "Renovada" en licenciamiento.html la licencia queda con
 * renovada = true y deja de enviarse.
 *
 * ── Despliegue (una sola vez) ───────────────────────────────────────────────
 * 1. Plan Blaze de Firebase (las funciones programadas lo exigen; con este uso el costo es casi 0).
 * 2. Azure / Entra ID (lo hace un administrador de 365):
 *      - Registrar una aplicación y crear un secreto de cliente.
 *      - Permisos de API → Microsoft Graph → Permisos de aplicación → Mail.Send → conceder consentimiento.
 *      - Recomendado: limitarla solo al buzón soporte@app.gov.co con una
 *        "Application Access Policy" de Exchange Online.
 * 3. En una carpeta "functions" con este archivo renombrado a index.js y este package.json:
 *      { "name": "functions", "main": "index.js", "engines": { "node": "20" },
 *        "dependencies": { "firebase-admin": "^12.0.0", "firebase-functions": "^5.0.0" } }
 * 4. Guardar los datos secretos (se piden por consola, no van en el código):
 *      firebase functions:secrets:set GRAPH_TENANT_ID
 *      firebase functions:secrets:set GRAPH_CLIENT_ID
 *      firebase functions:secrets:set GRAPH_CLIENT_SECRET
 * 5. Desplegar:  firebase deploy --only functions
 */
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { defineSecret } = require('firebase-functions/params');
const admin = require('firebase-admin');

admin.initializeApp();

const TENANT = defineSecret('GRAPH_TENANT_ID');
const CLIENT = defineSecret('GRAPH_CLIENT_ID');
const SECRET = defineSecret('GRAPH_CLIENT_SECRET');

const REMITENTE = 'soporte@app.gov.co';
const DESTINO = 'yoes934@gmail.com';
const DIAS_AVISO = 30;

function hoyBogota() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Bogota' }).format(new Date()); // AAAA-MM-DD
}
function diasEntre(desde, hasta) {
  return Math.round((Date.parse(hasta + 'T00:00:00Z') - Date.parse(desde + 'T00:00:00Z')) / 86400000);
}
function fmtFecha(v) { return v ? v.split('-').reverse().join('/') : ''; }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function dinero(n) { return new Intl.NumberFormat('es-CO', { style: 'currency', currency: 'COP', maximumFractionDigits: 2 }).format(n || 0); }

async function tokenGraph() {
  const r = await fetch('https://login.microsoftonline.com/' + TENANT.value() + '/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT.value(), client_secret: SECRET.value(),
      scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials'
    })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('No se obtuvo el token de Microsoft: ' + JSON.stringify(j));
  return j.access_token;
}

function cuerpo(l, dias) {
  const estado = dias < 0 ? 'VENCIDA hace ' + (-dias) + ' día(s)' : 'Vence en ' + dias + ' día(s)';
  const fila = function (k, v) { return '<tr><td style="padding:4px 12px 4px 0;color:#555"><b>' + k + '</b></td><td style="padding:4px 0">' + esc(v) + '</td></tr>'; };
  return '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">' +
    '<p><b>Aviso de vencimiento de licencia — ' + estado + '</b></p>' +
    '<table style="border-collapse:collapse">' +
    fila('Nombre Software', l.nombre) + fila('Fabricante', l.fabricante) + fila('Cantidad', l.cantidad) +
    fila('Año Compra', l.anioCompra) + fila('Fecha Activación', fmtFecha(l.fechaActivacion)) +
    fila('Fecha Vencimiento', fmtFecha(l.fechaVencimiento)) + fila('Días Faltante', dias) +
    fila('Tipo de Licencia', l.tipoLicencia) + fila('Contrato Asociado', l.contratoAsociado) +
    fila('Proveedor', l.proveedor) + fila('Valor Individual', dinero(l.valorIndividual)) +
    fila('Valor Total', dinero((l.cantidad || 0) * (l.valorIndividual || 0))) +
    fila('Observaciones', l.observaciones) + '</table>' +
    '<p style="color:#555">Este aviso se repite cada día hasta que la licencia se marque como «Renovada» en Inventario APP (licenciamiento.html).</p></div>';
}

exports.avisoLicencias = onSchedule(
  { schedule: 'every day 07:00', timeZone: 'America/Bogota', secrets: [TENANT, CLIENT, SECRET], region: 'us-central1' },
  async function () {
    const db = admin.firestore();
    const snap = await db.collection('licenciamiento').get();
    const hoy = hoyBogota();
    const pendientes = [];
    snap.forEach(function (d) {
      const l = d.data();
      if (l.renovada === true || !l.fechaVencimiento) return;
      const dias = diasEntre(hoy, l.fechaVencimiento);
      if (dias <= DIAS_AVISO) pendientes.push({ ref: d.ref, l: l, dias: dias });
    });
    if (!pendientes.length) { console.log('Sin licencias por avisar.'); return; }

    const token = await tokenGraph();
    for (const p of pendientes) {
      const asunto = (p.dias < 0 ? 'Licencia VENCIDA: ' : 'Licencia por vencer (' + p.dias + ' días): ') + p.l.nombre + ' — contrato ' + p.l.contratoAsociado;
      const r = await fetch('https://graph.microsoft.com/v1.0/users/' + REMITENTE + '/sendMail', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: { subject: asunto, body: { contentType: 'HTML', content: cuerpo(p.l, p.dias) }, toRecipients: [{ emailAddress: { address: DESTINO } }] },
          saveToSentItems: true
        })
      });
      if (r.status === 202) await p.ref.update({ ultimoAviso: admin.firestore.FieldValue.serverTimestamp() });
      else console.error('Falló el envío (' + p.l.contratoAsociado + '): ' + r.status + ' ' + (await r.text()));
    }
  }
);
