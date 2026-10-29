/* Служба качества, этап 1 — только просмотр сводки, которую публикует «Генератор протоколов».
   data/portal.enc = {v, salt, iv, iter, data} (base64): AES-256-GCM, ключ — PBKDF2-SHA256 из пароля сайта.
   Пароль — в sessionStorage до закрытия вкладки; тема — в localStorage. Адреса — через хеш: #/orders/ПР-26-206/equipment */
"use strict";

const DATA_URL = "data/portal.enc";
const PW_KEY = "sk-pw";
const THEME_KEY = "sk-theme";
const STALE_HOURS = 24;
const STAGES = ["Подготовка", "Испытания", "Комплект сформирован", "ПСИ", "Отгружено"];
const STAGE_VAR = { "Подготовка": "--st-prep", "Испытания": "--st-tests", "Комплект сформирован": "--st-kit",
                    "ПСИ": "--st-psi", "Отгружено": "--st-shipped" };
const SECTIONS = ["Маркировка", "Монтаж", "Документация", "ПО", "Прочее", "Сигналы", "Калибровка"];

let DATA = null;          // сводка
let ORDERS = [];          // ПР с вычисленными полями
let REMARKS = [];         // замечания всех ПР
let EVENTS = [];
const $ = (id) => document.getElementById(id);

// --------------------------------------------------------------------------- общие помощники

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function parseDate(s) {
  s = String(s || "").trim();
  let m = s.match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{1,2}):(\d{2}))?/);
  if (m) return new Date(+m[3], +m[2] - 1, +m[1], +(m[4] || 0), +(m[5] || 0));
  m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  return null;
}
const pad = (n) => String(n).padStart(2, "0");
function fmtDate(d) { return d ? `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}` : ""; }
function fmtDT(s) { const d = s instanceof Date ? s : parseDate(s); return d ? `${fmtDate(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}` : ""; }
function fmtDay(s) { const d = s instanceof Date ? s : parseDate(s); return d ? fmtDate(d) : ""; }
function dayStart(d) { return new Date(d.getFullYear(), d.getMonth(), d.getDate()); }
function today() { return dayStart(new Date()); }
function addDays(d, n) { return new Date(d.getFullYear(), d.getMonth(), d.getDate() + n); }
function dayKey(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
function plural(n, one, few, many) {
  const a = Math.abs(n) % 100, b = a % 10;
  return a > 10 && a < 20 ? many : b === 1 ? one : b >= 2 && b <= 4 ? few : many;
}
function ago(d) {
  if (!d) return "";
  const h = (Date.now() - d.getTime()) / 36e5;
  if (h < 1) return "меньше часа назад";
  if (h < 48) { const n = Math.floor(h); return `${n} ${plural(n, "час", "часа", "часов")} назад`; }
  const n = Math.floor(h / 24);
  return `${n} ${plural(n, "день", "дня", "дней")} назад`;
}
function dates(a, b) {
  return a && b && a !== b ? `${esc(a)} – ${esc(b)}` : esc(a || b || "");
}
function orderHref(o, tab, query) {
  return `#/orders/${encodeURIComponent(o.order_no)}${tab ? "/" + tab : ""}${query ? "?" + query : ""}`;
}
function stageHtml(stage) {
  return `<span class="stage"><i style="background:var(${STAGE_VAR[stage] || "--st-prep"})"></i>${esc(stage)}</span>`;
}
function badge(text, cls) { return `<span class="badge ${cls || ""}">${esc(text)}</span>`; }
function empty(text) { return `<div class="empty">${esc(text)}</div>`; }

// --------------------------------------------------------------------------- данные

function b64(s) { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }

async function decrypt(env, password) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(env.salt), iterations: env.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv) }, key, b64(env.data));
  return JSON.parse(new TextDecoder().decode(plain));
}

class LoadError extends Error {
  constructor(kind, text) { super(text); this.kind = kind; }
}

async function loadData(password) {
  let resp;
  try {
    resp = await fetch(`${DATA_URL}?t=${Date.now()}`, { cache: "no-store" });
  } catch (e) {
    throw new LoadError("network", "Не удалось загрузить сводку — проверьте подключение к интернету.");
  }
  if (resp.status === 404) throw new LoadError("nodata", "Сводка ещё не опубликована — в приложении: «Ещё» → «Опубликовать на портал».");
  if (!resp.ok) throw new LoadError("network", `Сводка не загрузилась (ответ сервера ${resp.status}). Повторите позже.`);
  let env;
  try { env = await resp.json(); } catch (e) { throw new LoadError("broken", "Файл сводки повреждён — опубликуйте её из приложения заново."); }
  try {
    return await decrypt(env, password);
  } catch (e) {
    throw new LoadError("password", "Неверный пароль");
  }
}

function sumSignals(units) {
  const s = units.filter((u) => u.signals).map((u) => u.signals);
  if (!s.length) return null;
  return s.reduce((a, b) => ({ total: a.total + b.total, checked: a.checked + b.checked, failed: a.failed + b.failed,
                               unreliable: a.unreliable + b.unreliable }), { total: 0, checked: 0, failed: 0, unreliable: 0 });
}

function prepare(data) {
  const now = new Date(), t0 = today();
  REMARKS = []; EVENTS = [];
  ORDERS = (data.orders || []).map((o) => {
    o.error = o.error || "";
    o.stageName = (o.stage && o.stage.current) || "Подготовка";
    o.archived = o.stageName === "Отгружено";
    o.equipment = o.equipment || []; o.pm = o.pm || []; o.remarks = o.remarks || []; o.testers = o.testers || [];
    o.events = o.events || [];
    o.units = o.equipment.reduce((n, e) => n + e.units.length, 0);
    o.sig = sumSignals(o.equipment.flatMap((e) => e.units));
    o.ziStart = parseDate(o.zi && o.zi.start); o.ziEnd = parseDate(o.zi && o.zi.end);
    o.psiStart = o.psi && o.psi.enabled ? parseDate(o.psi.start) : null;
    o.psiEnd = o.psi && o.psi.enabled ? parseDate(o.psi.end) : null;
    const upd = [o.updated && o.updated.trials, o.updated && o.updated.protocols].map(parseDate).filter(Boolean);
    o.updatedAt = upd.length ? new Date(Math.max(...upd)) : null;
    o.stale = o.stageName === "Испытания" && (!o.updatedAt || (now - o.updatedAt) / 36e5 > STALE_HOURS);
    o.remarks.forEach((r) => {
      r.order = o;
      r.dueDate = parseDate(r.due);
      r.overdue = r.open && r.dueDate && r.dueDate < t0;
      r.where = r.equipment ? `${r.equipment}${r.serial ? " зав. № " + r.serial : ""}` : r.pm ? r.pm : "общее";
      REMARKS.push(r);
    });
    o.open = o.remarks.filter((r) => r.open).length;
    o.overdue = o.remarks.filter((r) => r.overdue).length;
    o.pmFailed = o.pm.reduce((n, p) => n + p.failed + (p.own || []).reduce((m, x) => m + x.failed, 0), 0);
    o.events.forEach((e) => EVENTS.push(Object.assign({ order: o }, e)));
    return o;
  });
  ORDERS.sort((a, b) => (a.ziEnd ? a.ziEnd.getTime() : 9e15) - (b.ziEnd ? b.ziEnd.getTime() : 9e15) || a.order_no.localeCompare(b.order_no, "ru"));
  EVENTS.sort((a, b) => (b.time || "").localeCompare(a.time || ""));
  DATA = data;
  DATA.generatedAt = parseDate(data.generated);
}

function findOrder(no) { return ORDERS.find((o) => o.order_no === no); }

// --------------------------------------------------------------------------- куски разметки

function sigCell(s, compact, none) {
  if (!s) return `<span class="dim">${none || "нет Э4 / ТЭ5"}</span>`;
  if (!s.total) return '<span class="dim">нет сигналов</span>';
  const ok = s.checked - s.failed - s.unreliable;
  const w = (n) => (100 * n / s.total).toFixed(2) + "%";
  return `<div class="sig"><span class="nowrap"><b>${s.checked}</b> / ${s.total}</span>` +
    `${s.failed ? ` <span class="f nowrap">· не норма ${s.failed}</span>` : ""}` +
    `${s.unreliable ? ` <span class="u nowrap">· недостоверно ${s.unreliable}</span>` : ""}` +
    (compact ? "" : `<div class="prog" title="норма ${ok}, не норма ${s.failed}, недостоверно ${s.unreliable}, не проверено ${s.total - s.checked}">` +
      `<i class="ok" style="width:${w(ok)}"></i><i class="fail" style="width:${w(s.failed)}"></i><i class="unrel" style="width:${w(s.unreliable)}"></i></div>`) +
    "</div>";
}

function orderSig(o, compact) { return sigCell(o.sig, compact, o.has_trials ? "нет Э4 / ТЭ5" : "нет испытаний"); }
function pmLine(p) {
  const all = [p].concat(p.own || []);
  const items = all.reduce((n, x) => n + x.items, 0), done = all.reduce((n, x) => n + x.done, 0);
  const failed = all.reduce((n, x) => n + x.failed, 0), partial = all.reduce((n, x) => n + x.partial, 0);
  return `<div class="nowrap" title="${esc(p.code)}${p.title ? " — " + esc(p.title) : ""}">${esc(p.title ? p.title + " " + p.kind : p.code)}: ` +
    `<b>${done}</b> / ${items}${partial ? ` <span class="u">· частично ${partial}</span>` : ""}` +
    `${failed ? ` <span class="red">· не вып. ${failed}</span>` : ""}</div>`;
}
function pmCell(o) {
  if (!o.pm.length) return '<span class="dim">нет ПМ</span>';
  return `<div class="sig">${o.pm.map(pmLine).join("")}</div>`;
}
function remarksCell(o) {
  if (!o.open) return '<span class="dim">0</span>';
  return `${o.open}${o.overdue ? ` <span class="red nowrap">· просроч. ${o.overdue}</span>` : ""}`;
}
function ziCell(o) {
  const zi = o.zi && (o.zi.start || o.zi.end) ? dates(o.zi.start, o.zi.end) : '<span class="dim">план не задан</span>';
  const psi = o.psi && o.psi.enabled ? `<div class="small muted">ПСИ ${dates(o.psi.start, o.psi.end) || "без дат"}</div>` : "";
  return `<span class="nowrap">${zi}</span>${psi}`;
}
function updatedCell(o) {
  if (!o.updatedAt) return '<span class="dim">—</span>';
  return `<span class="nowrap">${fmtDT(o.updatedAt)}</span>${o.stale ? `<div>${badge("данные устарели", "warn")}</div>` : ""}`;
}
function responsible(o) {
  const r = o.responsible || {};
  return [r.tests, r.software].filter(Boolean).map(esc).join("<br>") || '<span class="dim">—</span>';
}
function footer() {
  return `<div class="footer">Сводка собрана ${esc(fmtDT(DATA.generatedAt))}${DATA.by ? ` (${esc(DATA.by)})` : ""} · данные приложения «Генератор протоколов»</div>`;
}
function table(head, rows, opts) {
  opts = opts || {};
  if (!rows.length) return empty(opts.empty || "Нет данных");
  return `<div class="table-wrap"><table><thead><tr>${head.map((h) => `<th${h.num ? ' class="num"' : ""}>${esc(h.t || h)}</th>`).join("")}</tr></thead>` +
    `<tbody>${rows.join("")}</tbody></table></div>`;
}
function linkRow(href, cells, cls) {
  return `<tr class="link ${cls || ""}" data-href="${esc(href)}">${cells.join("")}</tr>`;
}
function selectHtml(id, label, value, options) {
  return `<select class="select" id="${id}" aria-label="${esc(label)}"><option value="">${esc(label)}</option>` +
    options.map((o) => `<option value="${esc(o)}"${o === value ? " selected" : ""}>${esc(o)}</option>`).join("") + "</select>";
}
function tabsHtml(items, current) {
  return `<div class="tabs" role="tablist">${items.map((t) =>
    `<a href="${esc(t.href)}" role="tab" class="${t.key === current ? "sel" : ""}"${t.key === current ? ' aria-selected="true"' : ""}>${esc(t.title)}${t.n != null ? `<span class="n">${t.n}</span>` : ""}</a>`).join("")}</div>`;
}

// по дням: {"2026-10-29": [вручную, массово]} → столбики за 14 дней
function dayBars(byDay) {
  const end = today(), days = [];
  for (let i = 13; i >= 0; i--) { const d = addDays(end, -i); days.push([d, byDay[dayKey(d)] || [0, 0]]); }
  const max = Math.max(1, ...days.map(([, v]) => v[0] + v[1]));
  if (days.every(([, v]) => !v[0] && !v[1])) return empty("Отметок за 14 дней нет");
  const cols = days.map(([d, v]) => `<div class="col" title="${fmtDate(d)}: вручную ${v[0]}, массово ${v[1]}">` +
    `<i class="b" style="height:${(100 * v[1] / max).toFixed(1)}%"></i><i class="m" style="height:${(100 * v[0] / max).toFixed(1)}%"></i></div>`).join("");
  const xs = days.map(([d], i) => `<span>${i % 2 === 1 || days.length < 8 ? pad(d.getDate()) + "." + pad(d.getMonth() + 1) : ""}</span>`).join("");
  return `<div class="bars" role="img" aria-label="Отметки по дням за 14 дней">${cols}</div><div class="bars-x">${xs}</div>` +
    `<div class="legend"><span><i style="background:var(--accent)"></i>вручную</span><span><i style="background:var(--st-kit)"></i>массово</span></div>`;
}
function mergeDays(testers) {
  const out = {};
  testers.forEach((t) => Object.entries(t.by_day || {}).forEach(([k, v]) => {
    const a = out[k] || (out[k] = [0, 0]); a[0] += v[0]; a[1] += v[1];
  }));
  return out;
}

// --------------------------------------------------------------------------- навигация

const ICONS = {
  overview: '<path d="M4 13h6V4H4zM14 20h6v-9h-6zM4 20h6v-4H4zM14 4v4h6V4z"/>',
  orders: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/>',
  plan: '<rect x="4" y="5" width="16" height="15" rx="2"/><path d="M4 10h16M9 3v4M15 3v4"/>',
  tasks: '<path d="M9 6h11M9 12h11M9 18h11M4 6l1 1 2-2M4 12l1 1 2-2M4 18l1 1 2-2"/>',
  results: '<path d="M5 20V10M12 20V4M19 20v-7"/>',
  otk: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>',
  remarks: '<path d="M5 5h14v10H9l-4 4z"/>',
  analytics: '<path d="M4 19h16M6 15l4-5 4 3 5-7"/>',
};
const NAV = [
  ["Работа", [["overview", "Обзор", "#/"], ["orders", "Распоряжения", "#/orders"], ["plan", "План работ", "#/plan"],
              ["tasks", "Задачи", "#/tasks", true]]],
  ["Качество", [["results", "Результаты", "#/results"], ["otk", "ОТК", "#/otk", true], ["remarks", "Замечания", "#/remarks"],
                ["analytics", "Аналитика", "#/analytics"]]],
];

function renderNav(section) {
  const counts = { orders: ORDERS.filter((o) => !o.archived).length, remarks: REMARKS.filter((r) => r.open).length };
  $("nav").innerHTML = NAV.map(([cap, items]) => `<div class="caption">${esc(cap)}</div>` + items.map(([key, title, href, stub]) =>
    `<a href="${href}" class="${key === section ? "sel" : ""}"${key === section ? ' aria-current="page"' : ""}>` +
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[key]}</svg>` +
    `${esc(title)}${stub ? '<span class="stage2">этап 2</span>' : counts[key] ? `<span class="count">${counts[key]}</span>` : ""}</a>`).join("")).join("");
}

function parseRoute() {
  const h = location.hash.replace(/^#\/?/, "");
  const [path, qs] = h.split("?");
  return { parts: path.split("/").filter(Boolean).map(decodeURIComponent), q: new URLSearchParams(qs || "") };
}
function setQuery(changes) {
  const r = parseRoute();
  Object.entries(changes).forEach(([k, v]) => (v ? r.q.set(k, v) : r.q.delete(k)));
  const qs = r.q.toString();
  history.replaceState(null, "", "#/" + r.parts.map(encodeURIComponent).join("/") + (qs ? "?" + qs : ""));
  render();
}
function queryHref(changes) {
  const r = parseRoute();
  Object.entries(changes).forEach(([k, v]) => (v ? r.q.set(k, v) : r.q.delete(k)));
  const qs = r.q.toString();
  return "#/" + r.parts.map(encodeURIComponent).join("/") + (qs ? "?" + qs : "");
}

// --------------------------------------------------------------------------- экраны

function pageOverview() {
  const work = ORDERS.filter((o) => !o.archived);
  const open = REMARKS.filter((r) => r.open), overdue = open.filter((r) => r.overdue);
  const t0 = today();
  const next = work.filter((o) => o.ziEnd && o.ziEnd >= t0).sort((a, b) => a.ziEnd - b.ziEnd)[0];
  const kpi = `<div class="grid k3">
    <a class="card kpi" href="#/orders" style="color:inherit;text-decoration:none"><div class="label">ПР в работе</div>
      <div class="value">${work.length}</div><div class="sub">в архиве ${ORDERS.length - work.length}</div></a>
    <a class="card kpi" href="#/remarks?tab=open" style="color:inherit;text-decoration:none"><div class="label">Открытые замечания</div>
      <div class="value">${open.length}</div><div class="sub ${overdue.length ? "red" : ""}">просрочено ${overdue.length}</div></a>
    <div class="card kpi"><div class="label">Ближайшее окончание ЗИ</div>
      ${next ? `<div class="value">${fmtDate(next.ziEnd)}</div><div class="sub"><a href="${orderHref(next)}">${esc(next.order_no)}</a> · ${esc(next.object)}</div>`
             : '<div class="value dim">—</div><div class="sub">План не задан</div>'}</div></div>`;

  const att = [];
  ORDERS.forEach((o) => {
    if (o.error) att.push(["err", o, `сводка ПР не прочиталась: ${o.error}`, orderHref(o)]);
    if (o.archived) return;
    if (o.sig && o.sig.failed) att.push(["err", o, `сигналов «не норма»: ${o.sig.failed}`, orderHref(o, "equipment")]);
    if (o.sig && o.sig.unreliable) att.push(["warn", o, `сигналов «недостоверно» (испытатели отметили по-разному): ${o.sig.unreliable}`, orderHref(o, "equipment")]);
    if (o.overdue) att.push(["err", o, `просроченных замечаний: ${o.overdue}`, `#/remarks?tab=overdue&order=${encodeURIComponent(o.order_no)}`]);
    const errs = o.documents ? o.documents.issues.filter((i) => i.level === "error").length : 0;
    if (errs) att.push(["warn", o, `ошибок проверки комплекта: ${errs}`, orderHref(o, "documents")]);
    if (o.stale) att.push(["warn", o, `данные устарели — обновлены ${o.updatedAt ? ago(o.updatedAt) : "давно"}`, orderHref(o)]);
  });
  const attention = att.length ? `<ul class="list">${att.map(([lvl, o, text, href]) =>
    `<li><span class="dot ${lvl}"></span><span class="grow"><a href="${href}">${esc(o.order_no)}</a> ${o.object ? `<span class="muted">· ${esc(o.object)}</span>` : ""} — ${esc(text)}</span></li>`).join("")}</ul>`
    : empty("Всё в порядке: «не норма», просроченных замечаний и ошибок нет");

  const rows = work.slice(0, 10).map((o) => linkRow(orderHref(o), [
    `<td><a href="${orderHref(o)}">${esc(o.order_no)}</a><div class="small muted">${esc(o.object)}</div></td>`,
    `<td>${stageHtml(o.stageName)}</td>`, `<td>${orderSig(o)}</td>`, `<td>${pmCell(o)}</td>`,
    `<td class="num">${remarksCell(o)}</td>`, `<td>${ziCell(o)}</td>`]));
  const allTesters = ORDERS.flatMap((o) => o.testers);
  const events = EVENTS.slice(0, 10);
  return `<h1 class="title">Обзор</h1><p class="lead">Распоряжения в работе, ход испытаний и замечания — по данным приложения.</p>
    ${kpi}
    <div class="card"><h2>Требует внимания</h2>${attention}</div>
    <div class="card"><h2>Ближайшие ПР</h2>${table(["ПР", "Этап", "Сигналы", "Пункты ПМ", { t: "Замечания", num: true }, "Даты ЗИ"], rows, { empty: "ПР в работе нет" })}</div>
    <div class="grid c2">
      <div class="card"><h2>Отметки по дням</h2>${dayBars(mergeDays(allTesters))}</div>
      <div class="card"><h2>Последние события</h2>${events.length ? `<ul class="list">${events.map((e) =>
        `<li><span class="when">${esc(fmtDT(e.time))}</span><span class="grow"><a href="${orderHref(e.order, "history")}">${esc(e.order.order_no)}</a> — ${esc(e.text)}${e.who ? ` <span class="muted">· ${esc(e.who)}</span>` : ""}</span></li>`).join("")}</ul>` : empty("Событий нет")}</div>
    </div>`;
}

function pageOrders(q) {
  const tab = q.get("tab") === "archive" ? "archive" : "active";
  const text = (q.get("q") || "").trim().toLowerCase(), stage = q.get("stage") || "";
  const list = ORDERS.filter((o) => (tab === "archive") === o.archived).filter((o) => !stage || o.stageName === stage)
    .filter((o) => !text || [o.order_no, o.object, o.customer, ...o.equipment.map((e) => e.name), ...o.equipment.flatMap((e) => e.units.map((u) => u.serial))]
      .some((x) => String(x || "").toLowerCase().includes(text)));
  const rows = list.map((o) => linkRow(orderHref(o), [
    `<td><a href="${orderHref(o)}" class="nowrap">${esc(o.order_no)}</a>${o.error ? `<div>${badge("ошибка чтения", "err")}</div>` : ""}</td>`,
    `<td>${esc(o.object)}</td>`, `<td>${esc(o.customer)}</td>`, `<td class="small">${responsible(o)}</td>`,
    `<td class="num">${o.equipment.length} / ${o.units}</td>`, `<td>${stageHtml(o.stageName)}</td>`,
    `<td>${orderSig(o)}</td>`, `<td>${pmCell(o)}</td>`, `<td class="num">${remarksCell(o)}</td>`,
    `<td>${ziCell(o)}</td>`, `<td>${updatedCell(o)}</td>`]));
  const nActive = ORDERS.filter((o) => !o.archived).length;
  return `<h1 class="title">Распоряжения</h1>
    ${tabsHtml([{ key: "active", title: "В работе", href: "#/orders", n: nActive },
                { key: "archive", title: "Архив", href: "#/orders?tab=archive", n: ORDERS.length - nActive }], tab)}
    <div class="toolbar"><input class="input" id="f-q" type="search" placeholder="Поиск: № ПР, объект, заказчик, обозначение, зав. №" aria-label="Поиск" value="${esc(q.get("q") || "")}">
      ${selectHtml("f-stage", "Все этапы", stage, STAGES)}</div>
    ${table(["№ ПР", "Объект", "Заказчик", "Ответственные", { t: "Карточек / экз.", num: true }, "Этап", "Сигналы", "Пункты ПМ",
             { t: "Замечания", num: true }, "Даты ЗИ (ПСИ)", "Обновлено"], rows,
            { empty: text || stage ? "Ничего не найдено" : tab === "archive" ? "Отгруженных ПР нет" : "ПР в работе нет" })}`;
}

function pageOrder(o, tab, q) {
  const tabs = [["overview", "Обзор"], ["equipment", "Оборудование"], ["documents", "Документы"], ["remarks", "Замечания"], ["history", "История"]];
  tab = tabs.some(([k]) => k === tab) ? tab : "overview";
  const head = `<div class="title-row"><h1 class="title">${esc(o.order_no)}</h1>${stageHtml(o.stageName)}${o.stale ? badge("данные устарели", "warn") : ""}</div>
    <p class="lead">${esc(o.object || "объект не указан")}${o.customer ? " · " + esc(o.customer) : ""}</p>
    ${tabsHtml(tabs.map(([k, t]) => ({ key: k, title: t, href: orderHref(o, k === "overview" ? "" : k), n: k === "remarks" ? o.open || null : null })), tab)}`;
  const notes = [];
  if (o.error) notes.push(`<div class="banner err">Сводка этого ПР не прочиталась в приложении: ${esc(o.error)}</div>`);
  if (!o.error && !o.has_trials) notes.push('<div class="banner info">Испытаний этого ПР в приложении нет — сигналов и отметок испытателей не будет.</div>');
  if (!o.error && !o.has_project) notes.push('<div class="banner info">Проекта «Протоколов» нет — документы ещё не готовятся.</div>');
  if (o.stale) notes.push(`<div class="banner warn">Данные устарели: испытания идут, а сводка обновлялась ${o.updatedAt ? ago(o.updatedAt) : "давно"}.</div>`);
  const body = { overview: orderOverview, equipment: orderEquipment, documents: orderDocuments, remarks: (x) => remarksView(q, x), history: orderHistory }[tab](o);
  return head + notes.join("") + body;
}

function orderOverview(o) {
  const m = o.zi || {}, c = o.conditions || {}, r = o.responsible || {};
  const hist = (o.stage && o.stage.history) || [];
  const docs = o.documents;
  const server = o.server_folder ? `<div class="path"><code id="srv">${esc(o.server_folder)}</code><button class="btn" type="button" data-copy="${esc(o.server_folder)}">Копировать</button></div>
      <div class="small muted" style="margin-top:6px">Открывается только из внутренней сети.</div>` : '<span class="dim">не найдена (папка проектов на сервере не задана в приложении или нет папки этого ПР)</span>';
  return `<div class="grid c2">
    <div class="card"><h2>Реквизиты</h2><dl class="props">
      <dt>Заказчик</dt><dd>${esc(o.customer) || "—"}</dd><dt>Пользователь</dt><dd>${esc(o.user) || "—"}</dd>
      <dt>Объект</dt><dd>${esc(o.object) || "—"}</dd><dt>Договор</dt><dd>${esc(o.contract) || "—"}</dd>
      <dt>Основание</dt><dd>${esc(o.basis) || "—"}</dd></dl></div>
    <div class="card"><h2>Показатели</h2><dl class="props">
      <dt>Сигналы</dt><dd>${orderSig(o)}</dd>
      <dt>Пункты ПМ</dt><dd>${pmCell(o)}</dd>
      <dt>Замечания</dt><dd>открыто ${o.open}${o.overdue ? `, <span class="red">просрочено ${o.overdue}</span>` : ""}, всего ${o.remarks.length}</dd>
      <dt>Документы</dt><dd>${docs ? `будет ${docs.planned}, без замечаний ${docs.clean}` : '<span class="dim">проекта нет</span>'}</dd>
      <dt>Обновлено</dt><dd>испытания: ${o.updated && o.updated.trials ? esc(fmtDT(o.updated.trials)) : "—"}<br>протоколы: ${o.updated && o.updated.protocols ? esc(fmtDT(o.updated.protocols)) : "—"}</dd></dl></div>
    <div class="card"><h2>Этап</h2><div style="margin-bottom:8px">${stageHtml(o.stageName)}</div>
      ${hist.length ? `<ul class="list">${hist.slice().reverse().map((h) => `<li><span class="when">${esc(fmtDT(h.time))}</span><span class="grow">${esc(h.stage)}${h.who ? ` <span class="muted">· ${esc(h.who)}</span>` : ""}</span></li>`).join("")}</ul>` : empty("Этап ещё не менялся")}</div>
    <div class="card"><h2>Ответственные, даты, условия</h2><dl class="props">
      <dt>Служба качества</dt><dd>${esc(r.tests) || "—"}</dd><dt>Проект (ПО)</dt><dd>${esc(r.software) || "—"}</dd>
      <dt>Даты ЗИ</dt><dd>${m.start || m.end ? dates(m.start, m.end) : '<span class="dim">план не задан</span>'}</dd>
      <dt>ПСИ</dt><dd>${o.psi && o.psi.enabled ? dates(o.psi.start, o.psi.end) || "включены, без дат" : '<span class="dim">не включены</span>'}</dd>
      <dt>Условия</dt><dd>${[c.temperature && `${esc(c.temperature)} °C`, c.humidity && `${esc(c.humidity)} %`, c.pressure && `${esc(c.pressure)} кПа`].filter(Boolean).join(", ") || "—"}</dd></dl></div>
  </div>
  <div class="card"><h2>Папка проекта на сервере</h2>${server}</div>`;
}

function orderEquipment(o) {
  const cards = o.equipment.map((e) => {
    const rows = e.units.map((u) => {
      const cal = u.calibration;
      return `<tr><td class="nowrap">${esc(u.serial) || '<span class="dim">без зав. №</span>'}</td><td>${sigCell(u.signals, false, o.has_trials ? "нет Э4 / ТЭ5" : "нет испытаний")}</td>
        <td>${cal ? `${cal.channels} кан.${cal.failed ? ` <span class="red nowrap">· не норма ${cal.failed}</span>` : ""}${cal.empty ? ` <span class="muted nowrap">· не заполнено ${cal.empty}</span>` : ""}` : '<span class="dim">—</span>'}</td>
        <td class="num">${u.remarks_open ? `<a href="#/orders/${encodeURIComponent(o.order_no)}/remarks?tab=open&q=${encodeURIComponent(u.serial || "")}">${u.remarks_open}</a>` : '<span class="dim">0</span>'}</td></tr>`;
    });
    const mism = e.mismatches == null ? '<span class="dim">сверка с базой не проводилась</span>'
      : e.mismatches ? `<span class="badge warn">несоответствий сверки с базой: ${e.mismatches}</span>` : badge("сверка с базой без несоответствий", "ok");
    return `<div class="card"><div class="title-row"><h2 style="margin:0">${esc(e.name)}</h2>${e.kind ? badge(e.kind) : ""}</div>
      <div class="small muted" style="margin:4px 0 10px">${e.tu ? esc(e.tu) + " · " : ""}${mism}</div>
      ${table(["Зав. №", "Сигналы", "Калибровка", { t: "Открытые замечания", num: true }], rows)}</div>`;
  });
  const pmRows = o.pm.flatMap((p) => [`<tr><td>${esc(p.code)}<div class="small muted">${esc(p.kind)}${p.title ? " · " + esc(p.title) : ""}</div></td>
      <td class="small">${esc(p.equipment) || '<span class="dim">—</span>'}</td><td class="num">${p.done}</td><td class="num">${p.partial || '<span class="dim">0</span>'}</td>
      <td class="num">${p.failed ? `<span class="red">${p.failed}</span>` : '<span class="dim">0</span>'}</td><td class="num">${p.items}</td></tr>`]
    .concat((p.own || []).map((x) => `<tr class="sub"><td>свои отметки</td><td class="small">${esc(x.equipment)} зав. № ${esc(x.serial)}</td>
      <td class="num">${x.done}</td><td class="num">${x.partial}</td><td class="num">${x.failed ? `<span class="red">${x.failed}</span>` : 0}</td><td class="num">${x.items}</td></tr>`)));
  return (cards.length ? cards.join("") : `<div class="card">${empty("Оборудования нет")}</div>`) +
    `<div class="card"><h2>Программы и методики</h2>${table(["ПМ", "Оборудование", { t: "Выполнено", num: true }, { t: "Частично", num: true },
      { t: "Не выполнено", num: true }, { t: "Всего пунктов", num: true }], pmRows, { empty: "ПМ не загружены" })}</div>`;
}

function orderDocuments(o) {
  const d = o.documents;
  if (!d) return `<div class="card">${empty("Проекта «Протоколов» нет — документы ещё не готовятся")}</div>`;
  const has = (k) => (d.files[k] ? badge("есть", "ok") : badge("нет"));
  const issues = d.issues.length ? `<ul class="list">${d.issues.map((i) => `<li><span class="dot ${i.level === "error" ? "err" : "warn"}"></span><span class="grow"><b>${esc(i.title)}</b>: ${esc(i.text)}</span></li>`).join("")}</ul>` : empty("Проблем нет");
  const cls = { "Готово": "ok", "Не хватает": "err", "Внимание": "warn" };
  const ship = d.shipment.map((r) => `<tr><td class="nowrap">${esc(r.section)}</td><td>${esc(r.item)}</td><td>${badge(r.status, cls[r.status])}</td><td><div class="clamp" title="${esc(r.note)}">${esc(r.note)}</div></td></tr>`);
  return `<div class="grid k3">
    <div class="card kpi"><div class="label">Документов будет</div><div class="value">${d.planned}</div><div class="sub">без замечаний проверки ${d.clean}</div></div>
    <div class="card kpi"><div class="label">Комплект сформирован</div><div class="value" style="font-size:20px">${d.generated ? esc(fmtDT(d.generated)) : '<span class="dim">не формировался</span>'}</div>
      <div class="sub">Акт ЗИ ${has("act")} Протокол ЗИ ${has("zi_protocol")}${o.psi && o.psi.enabled ? `<br>Акт ПСИ ${has("psi_act")} Протокол ПСИ ${has("psi_protocol")}` : ""}</div></div>
    <div class="card kpi"><div class="label">Готово к отгрузке</div><div class="value">${d.ready ? '<span style="color:var(--ok)">да</span>' : '<span class="red">нет</span>'}</div>
      <div class="sub">по «Контролю отгрузки»; не хватает позиций: ${d.shipment.filter((r) => r.status === "Не хватает").length}</div></div></div>
    <div class="card"><h2>Проблемы проверки</h2>${issues}</div>
    <div class="card"><h2>Контроль отгрузки</h2>${table(["Раздел", "Позиция", "Статус", "Комментарий"], ship, { empty: "Нет позиций" })}</div>
    <p class="small muted">Файлов на портале нет — документы лежат в папке проекта на сервере (вкладка «Обзор»).</p>`;
}

function orderHistory(o) {
  if (!o.events.length) return `<div class="card">${empty("Событий нет")}</div>`;
  const cls = { "этап": "info", "комплект": "ok", "правка": "", "выгрузка": "" };
  return `<div class="card"><ul class="list">${o.events.map((e) => `<li><span class="when">${esc(fmtDT(e.time))}</span>${badge(e.kind, cls[e.kind])}<span class="grow">${esc(e.text)}${e.who ? ` <span class="muted">· ${esc(e.who)}</span>` : ""}</span></li>`).join("")}</ul></div>`;
}

// --- замечания (общий список и вкладка ПР)
function remarkStatus(r) {
  if (!r.open) return badge(r.status && r.status !== "исправлено" ? `${r.status} · закрыто` : "закрыто", "ok");
  const cls = { "дефицит": "warn", "в работе": "info", "не реализовано": "err", "принято к рассмотрению": "" };
  return badge(r.status || "в работе", cls[r.status]);
}
function remarksView(q, order) {
  const tab = ["open", "overdue", "psi"].includes(q.get("tab")) ? q.get("tab") : "all";
  const base = order ? order.remarks : REMARKS;
  const text = (q.get("q") || "").trim().toLowerCase();
  const f = { order: q.get("order") || "", section: q.get("section") || "", status: q.get("status") || "", owner: q.get("owner") || "", pm: q.get("pm") || "" };
  const byTab = { all: () => true, open: (r) => r.open, overdue: (r) => r.overdue, psi: (r) => r.psi };
  const list = base.filter(byTab[tab])
    .filter((r) => !f.order || r.order.order_no === f.order).filter((r) => !f.section || (r.section || "—") === f.section)
    .filter((r) => !f.status || (r.open ? r.status : "закрыто") === f.status).filter((r) => !f.owner || r.owner === f.owner)
    .filter((r) => !f.pm || r.pm === f.pm)
    .filter((r) => !text || [r.text, r.where, r.owner, r.author, r.signal, r.cabinet, r.order.order_no].some((x) => String(x || "").toLowerCase().includes(text)))
    .sort((a, b) => (b.overdue - a.overdue) || (b.open - a.open) || String(b.time || "").localeCompare(String(a.time || "")));
  const uniq = (fn) => [...new Set(base.map(fn).filter(Boolean))].sort((a, b) => a.localeCompare(b, "ru"));
  const href = (k) => queryHref({ tab: k === "all" ? "" : k, id: "" });
  const tabs = tabsHtml([["all", "Все", base.length], ["open", "Открытые", base.filter((r) => r.open).length],
    ["overdue", "Просроченные", base.filter((r) => r.overdue).length], ["psi", "ПСИ", base.filter((r) => r.psi).length]]
    .map(([k, t, n]) => ({ key: k, title: t, n, href: href(k) })), tab);
  const filters = `<div class="toolbar"><input class="input" id="f-q" type="search" placeholder="Поиск по тексту, оборудованию, «кому»" aria-label="Поиск" value="${esc(q.get("q") || "")}">
    ${order ? "" : selectHtml("f-order", "Все ПР", f.order, uniq((r) => r.order.order_no))}
    ${selectHtml("f-section", "Все разделы", f.section, [...new Set(SECTIONS.concat(uniq((r) => r.section || "—")))].filter((s) => base.some((r) => (r.section || "—") === s)))}
    ${selectHtml("f-status", "Все статусы", f.status, uniq((r) => (r.open ? r.status : "закрыто")))}
    ${selectHtml("f-owner", "Кому — все", f.owner, uniq((r) => r.owner))}
    ${f.pm ? `<a class="btn" href="${queryHref({ pm: "" })}">ПМ: ${esc(f.pm)} ✕</a>` : ""}</div>`;
  const rows = list.map((r) => linkRow(queryHref({ id: r.id }), [
    order ? "" : `<td class="nowrap"><a href="${orderHref(r.order)}">${esc(r.order.order_no)}</a></td>`,
    `<td>${esc(r.where)}${r.pm && r.equipment ? `<div class="small muted">${esc(r.pm)}</div>` : ""}</td>`,
    `<td class="nowrap">${esc(r.section) || '<span class="dim">—</span>'}</td>`,
    `<td><div class="clamp">${esc(r.text)}</div></td>`, `<td>${remarkStatus(r)}</td>`,
    `<td>${esc(r.owner) || '<span class="dim">—</span>'}</td>`,
    `<td class="nowrap ${r.overdue ? "red" : ""}">${esc(r.due) || '<span class="dim">—</span>'}</td>`,
    `<td class="small">${r.closed_by || r.closed_time ? `${esc(r.closed_by)}${r.closed_time ? "<br>" + esc(fmtDay(r.closed_time)) : ""}` : '<span class="dim">—</span>'}</td>`,
    `<td class="small">${esc(r.author) || '<span class="dim">—</span>'}</td>`]));
  const head = (order ? [] : ["ПР"]).concat(["Оборудование, зав. № / ПМ", "Раздел", "Замечание", "Статус", "Кому", "Срок", "Закрыто", "Автор"]);
  return tabs + filters + table(head, rows, { empty: base.length ? "Ничего не найдено" : "Замечаний нет" });
}
function pageRemarks(q) {
  return `<h1 class="title">Замечания</h1><p class="lead">Из испытаний, протоколов ЗИ и ПСИ всех ПР. «Кому», «срок» и «закрыто» — внутренние, в протоколы не попадают.</p>` + remarksView(q, null);
}

function remarkPanel(id) {
  const r = REMARKS.find((x) => x.id === id);
  if (!r) return "";
  const hist = [[r.time, `создано${r.author ? " — " + r.author : ""}`]];
  if (r.closed_by || r.closed_time) hist.push([r.closed_time, `закрыто${r.closed_by ? " — " + r.closed_by : ""}`]);
  return `<div class="panel-scrim" data-close-panel></div>
    <aside class="panel" role="dialog" aria-modal="true" aria-labelledby="panel-title">
      <header><h2 id="panel-title">Замечание</h2><button class="btn ghost icon" type="button" data-close-panel aria-label="Закрыть">✕</button></header>
      <div class="body"><p class="text">${esc(r.text)}</p>
        <dl class="props">
          <dt>ПР</dt><dd><a href="${orderHref(r.order)}">${esc(r.order.order_no)}</a> · ${esc(r.order.object)}</dd>
          <dt>Оборудование</dt><dd>${r.equipment ? esc(r.where) : '<span class="dim">—</span>'}</dd>
          ${r.pm ? `<dt>ПМ</dt><dd>${esc(r.pm)}</dd>` : ""}
          ${r.cabinet ? `<dt>Шкаф</dt><dd>${esc(r.cabinet)}</dd>` : ""}
          ${r.signal ? `<dt>Сигнал</dt><dd>${esc(r.signal)}</dd>` : ""}
          <dt>Раздел</dt><dd>${esc(r.section) || "—"}</dd>
          <dt>Источник</dt><dd>${esc((r.sources || []).join(", ")) || "—"}</dd>
          <dt>Статус</dt><dd>${remarkStatus(r)}</dd>
          <dt>Кому</dt><dd>${esc(r.owner) || "—"}</dd>
          <dt>Срок</dt><dd class="${r.overdue ? "red" : ""}">${esc(r.due) || "—"}${r.overdue ? " · просрочено" : ""}</dd>
          <dt>Закрыто</dt><dd>${r.closed_by || r.closed_time ? `${esc(r.closed_by)} ${esc(fmtDT(r.closed_time))}` : "—"}</dd>
          <dt>Автор</dt><dd>${esc(r.author) || "—"}${r.time ? ` · ${esc(fmtDT(r.time))}` : ""}</dd>
        </dl>
        <h2 style="margin-top:18px">История</h2>
        <ul class="list">${hist.map(([t, s]) => `<li><span class="when">${esc(fmtDT(t)) || "—"}</span><span class="grow">${esc(s)}</span></li>`).join("")}</ul>
      </div></aside>`;
}

// --- план работ
function pagePlan(q) {
  const view = q.get("view") === "table" ? "table" : "calendar";
  const tabs = tabsHtml([{ key: "calendar", title: "Календарь", href: "#/plan" }, { key: "table", title: "Таблица", href: "#/plan?view=table" }], view);
  const list = ORDERS.filter((o) => !o.archived);
  const noPlan = list.filter((o) => !o.ziStart && !o.ziEnd && !o.psiStart && !o.psiEnd);
  if (view === "table") {
    const rows = ORDERS.map((o) => linkRow(orderHref(o), [
      `<td class="nowrap"><a href="${orderHref(o)}">${esc(o.order_no)}</a></td>`, `<td>${esc(o.object)}</td>`,
      `<td class="nowrap">${o.zi.start || o.zi.end ? dates(o.zi.start, o.zi.end) : '<span class="dim">не задано</span>'}</td>`,
      `<td class="nowrap">${o.psi.enabled ? dates(o.psi.start, o.psi.end) || "без дат" : '<span class="dim">—</span>'}</td>`,
      `<td>${stageHtml(o.stageName)}</td>`, `<td>${orderSig(o, true)}</td>`, `<td>${pmCell(o)}</td>`,
      `<td class="small">${esc((o.responsible || {}).tests) || '<span class="dim">—</span>'}</td>`]));
    return `<h1 class="title">План работ</h1><p class="lead">По датам ЗИ и ПСИ из реквизитов ПР. Срока сдачи в приложении нет.</p>${tabs}` +
      table(["ПР", "Объект", "ЗИ с–по", "ПСИ с–по", "Этап", "Сигналы", "Пункты ПМ", "Ответственный"], rows, { empty: "ПР нет" });
  }
  const scale = q.get("scale") === "month" ? "month" : "weeks";
  const shift = parseInt(q.get("shift") || "0", 10) || 0;
  const t0 = today();
  let start, days;
  if (scale === "month") {
    start = new Date(t0.getFullYear(), t0.getMonth() + shift, 1);
    days = new Date(start.getFullYear(), start.getMonth() + 1, 0).getDate();
  } else {
    const monday = addDays(t0, -((t0.getDay() + 6) % 7));
    start = addDays(monday, -7 + shift * 7);
    days = 42;
  }
  const end = addDays(start, days);   // не включая
  const dated = list.filter((o) => !noPlan.includes(o));
  const col = (d) => Math.round((dayStart(d) - start) / 864e5);
  const bar = (a, b, cls, color, label) => {
    a = a || b; b = b || a;
    if (!a || b < start || a >= end) return "";
    const s = Math.max(0, col(a)), e = Math.min(days, col(b) + 1);
    return `<div class="bar ${cls}" style="left:calc(${s} * 100% / ${days});width:calc(${e - s} * 100% / ${days} - 2px);${color ? `background:var(${color})` : ""}" title="${esc(label)}">${esc(label)}</div>`;
  };
  const heads = [];
  for (let i = 0; i < days; i++) {
    const d = addDays(start, i), we = d.getDay() === 0 || d.getDay() === 6, isToday = +d === +t0;
    heads.push(`<div class="head${we ? " we" : ""}${isToday ? " today" : ""}" style="grid-column:${i + 2}">${scale === "month" || d.getDay() === 1 || i === 0 ? pad(d.getDate()) + (scale === "weeks" ? "." + pad(d.getMonth() + 1) : "") : ""}</div>`);
  }
  const todayLine = t0 >= start && t0 < end ? `<div class="today-line" style="left:calc(${col(t0) + 0.5} * 100% / ${days})"></div>` : "";
  const rows = dated.map((o, i) => `<div class="label" style="grid-row:${i + 2}"><a href="${orderHref(o)}">${esc(o.order_no)}</a><div>${esc(o.object)}</div></div>
    <div class="lane" style="grid-row:${i + 2};grid-column:2 / span ${days};height:${o.psi.enabled ? 50 : 34}px">${todayLine}
      ${bar(o.ziStart, o.ziEnd, "zi", STAGE_VAR[o.stageName], `ЗИ ${fmtDate(o.ziStart || o.ziEnd)}${o.ziEnd && o.ziStart && +o.ziEnd !== +o.ziStart ? " – " + fmtDate(o.ziEnd) : ""}`)}
      ${o.psi.enabled ? bar(o.psiStart, o.psiEnd, "psi", "", `ПСИ ${fmtDate(o.psiStart || o.psiEnd)}`) : ""}</div>`).join("");
  const months = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"];
  const period = scale === "month" ? `${months[start.getMonth()]} ${start.getFullYear()}` : `${fmtDate(start)} – ${fmtDate(addDays(end, -1))}`;
  const ctrl = `<div class="toolbar"><div class="seg"><a href="${queryHref({ scale: "", shift: "" })}" class="${scale === "weeks" ? "sel" : ""}">Недели</a><a href="${queryHref({ scale: "month", shift: "" })}" class="${scale === "month" ? "sel" : ""}">Месяц</a></div>
    <a class="btn" href="${queryHref({ shift: String(shift - 1) })}" aria-label="Раньше">‹</a><a class="btn" href="${queryHref({ shift: "" })}">Сегодня</a><a class="btn" href="${queryHref({ shift: String(shift + 1) })}" aria-label="Позже">›</a>
    <b style="margin-left:6px">${esc(period)}</b></div>`;
  const legend = `<div class="legend">${STAGES.map((s) => `<span><i style="background:var(${STAGE_VAR[s]})"></i>${esc(s)}</span>`).join("")}<span><i style="background:repeating-linear-gradient(135deg,var(--st-psi) 0 3px,transparent 3px 5px);border:1px solid var(--st-psi)"></i>даты ПСИ</span><span><i style="background:var(--err)"></i>сегодня</span></div>`;
  return `<h1 class="title">План работ</h1><p class="lead">Полоса ПР — от начала до окончания ЗИ, ниже — ПСИ; цвет — по этапу.</p>${tabs}${ctrl}
    ${dated.length ? `<div class="gantt"><div class="gantt-grid" style="grid-template-columns:minmax(150px,200px) repeat(${days}, minmax(${scale === "month" ? 22 : 16}px, 1fr))">
      <div class="head" style="grid-column:1;text-align:left;padding-left:12px">ПР</div>${heads.join("")}${rows}</div></div>${legend}` : empty("План не задан: у ПР в работе нет дат ЗИ и ПСИ")}
    <div class="card"><h2>План не задан</h2>${noPlan.length ? `<ul class="list">${noPlan.map((o) => `<li><span class="grow"><a href="${orderHref(o)}">${esc(o.order_no)}</a> <span class="muted">· ${esc(o.object)}</span></span>${stageHtml(o.stageName)}</li>`).join("")}</ul>` : empty("У всех ПР в работе есть даты")}</div>`;
}

function pageResults() {
  const rows = ORDERS.map((o) => {
    const d = o.documents;
    return linkRow(orderHref(o, "documents"), [
      `<td><a href="${orderHref(o, "documents")}" class="nowrap">${esc(o.order_no)}</a><div class="small muted">${esc(o.object)}</div></td>`,
      `<td>${stageHtml(o.stageName)}</td>`, `<td>${orderSig(o)}</td>`, `<td>${pmCell(o)}</td>`,
      `<td class="num">${d ? `${d.planned} / ${d.clean}` : '<span class="dim">—</span>'}</td>`,
      `<td class="nowrap">${d && d.generated ? esc(fmtDT(d.generated)) : '<span class="dim">не формировался</span>'}</td>`,
      `<td class="nowrap">${o.psi.enabled ? (d && d.files.psi_act && d.files.psi_protocol ? badge("акт и протокол", "ok") : badge("включены")) : '<span class="dim">—</span>'}</td>`,
      `<td>${d ? (d.ready ? badge("да", "ok") : badge("нет", "err")) : '<span class="dim">—</span>'}</td>`]);
  });
  return `<h1 class="title">Результаты</h1><p class="lead">Отрицательный результат виден и при полном объёме; готовность — только по «Контролю отгрузки».</p>` +
    table(["ПР", "Этап", "Сигналы", "Пункты ПМ", { t: "Документы: будет / без замечаний", num: true }, "Комплект сформирован", "ПСИ", "Готово к отгрузке"], rows, { empty: "ПР нет" });
}

// --- аналитика
function pageAnalytics(q) {
  const tab = q.get("tab") === "testers" ? "testers" : "remarks";
  const tabs = tabsHtml([{ key: "remarks", title: "Замечания", href: "#/analytics" }, { key: "testers", title: "Испытатели", href: "#/analytics?tab=testers" }], tab);
  if (tab === "testers") return `<h1 class="title">Аналитика</h1>${tabs}` + analyticsTesters(q);
  const link = (params, n) => n ? `<a href="#/remarks?${new URLSearchParams(params)}">${n}</a>` : '<span class="dim">0</span>';
  const byOrder = ORDERS.filter((o) => o.remarks.length).map((o) => `<tr><td><a href="${orderHref(o)}">${esc(o.order_no)}</a></td>
    <td class="num">${link({ order: o.order_no }, o.remarks.length)}</td><td class="num">${link({ tab: "open", order: o.order_no }, o.open)}</td>
    <td class="num">${o.overdue ? `<span class="red">${link({ tab: "overdue", order: o.order_no }, o.overdue)}</span>` : '<span class="dim">0</span>'}</td></tr>`);
  const groupRows = (fn, key) => {
    const m = new Map();
    REMARKS.forEach((r) => { const k = fn(r); const a = m.get(k) || [0, 0, 0]; a[0]++; a[1] += r.open; a[2] += r.overdue ? 1 : 0; m.set(k, a); });
    return [...m.entries()].sort((a, b) => b[1][0] - a[1][0]).map(([k, [all, open, over]]) => `<tr><td>${esc(k)}</td>
      <td class="num">${link({ [key]: k }, all)}</td><td class="num">${link({ tab: "open", [key]: k }, open)}</td>
      <td class="num">${over ? `<span class="red">${link({ tab: "overdue", [key]: k }, over)}</span>` : '<span class="dim">0</span>'}</td></tr>`);
  };
  const head = ["", { t: "Всего", num: true }, { t: "Открытые", num: true }, { t: "Просроченные", num: true }];
  const pm = new Map();
  REMARKS.filter((r) => r.pm).forEach((r) => { const s = pm.get(r.pm) || new Map(); s.set(r.order.order_no, (s.get(r.order.order_no) || 0) + 1); pm.set(r.pm, s); });
  const repeat = [...pm.entries()].filter(([, s]) => s.size > 1).map(([code, s]) => `<tr><td>${esc(code)}</td>
    <td>${[...s.entries()].map(([no, n]) => `<a href="#/remarks?${new URLSearchParams({ order: no, pm: code })}">${esc(no)}</a> (${n})`).join(", ")}</td>
    <td class="num"><a href="#/remarks?${new URLSearchParams({ pm: code })}">${[...s.values()].reduce((a, b) => a + b, 0)}</a></td></tr>`);
  return `<h1 class="title">Аналитика</h1>${tabs}
    <div class="grid c2">
      <div class="card"><h2>По ПР</h2>${table(["ПР"].concat(head.slice(1)), byOrder, { empty: "Замечаний нет" })}</div>
      <div class="card"><h2>По разделам</h2>${table(["Раздел"].concat(head.slice(1)), groupRows((r) => r.section || "—", "section"), { empty: "Замечаний нет" })}</div>
      <div class="card"><h2>По статусам</h2>${table(["Статус"].concat(head.slice(1)), groupRows((r) => (r.open ? r.status || "в работе" : "закрыто"), "status"), { empty: "Замечаний нет" })}</div>
      <div class="card"><h2>Повторяются по одной ПМ в разных ПР</h2>${table(["ПМ", "ПР (замечаний)", { t: "Всего", num: true }], repeat, { empty: "Повторов нет" })}</div>
    </div>`;
}

function analyticsTesters(q) {
  const people = new Map();
  ORDERS.forEach((o) => o.testers.forEach((t) => {
    const p = people.get(t.name) || { name: t.name, rows: [], signals: 0, bulk: 0, auto: 0, points: 0, failed: 0, unreliable: 0, remarks: 0, first: "", last: "" };
    p.rows.push([o, t]);
    ["signals", "bulk", "auto", "points", "failed", "unreliable", "remarks"].forEach((k) => (p[k] += t[k] || 0));
    if (t.first && (!p.first || t.first < p.first)) p.first = t.first;
    if (t.last && t.last > p.last) p.last = t.last;
    people.set(t.name, p);
  }));
  const list = [...people.values()].sort((a, b) => b.signals - a.signals);
  const who = q.get("who") || "";
  const rows = list.flatMap((p) => {
    const inWork = p.rows.filter(([o]) => !o.archived).length;
    return [`<tr><td><b>${esc(p.name)}</b></td><td class="num">${inWork}</td><td class="num">${p.signals - p.bulk}</td><td class="num">${p.bulk}</td>
      <td class="num">${p.auto}</td><td class="num">${p.points}</td><td class="num">${p.failed ? `<span class="red">${p.failed}</span>` : 0}</td>
      <td class="num">${p.unreliable}</td><td class="num">${p.remarks}</td><td class="nowrap small">${esc(fmtDT(p.first))}<br>${esc(fmtDT(p.last))}</td></tr>`]
      .concat(p.rows.map(([o, t]) => `<tr class="sub"><td><a href="${orderHref(o)}">${esc(o.order_no)}</a></td><td class="num">${o.archived ? "архив" : stageHtml(o.stageName)}</td>
        <td class="num">${t.signals - t.bulk}</td><td class="num">${t.bulk}</td><td class="num">${t.auto}</td><td class="num">${t.points}</td>
        <td class="num">${t.failed}</td><td class="num">${t.unreliable}</td><td class="num">${t.remarks}</td><td class="nowrap small">${esc(fmtDT(t.first))}<br>${esc(fmtDT(t.last))}</td></tr>`));
  });
  const chosen = who ? list.filter((p) => p.name === who) : list;
  return `<div class="banner info">Это не загрузка в часах и не оценка работы: отметки показывают, что и когда отмечено, массовые отметки («Норма для показанных», несколько строк сразу) — отдельно.</div>
    <div class="card"><h2>Испытатели</h2>${table(["Испытатель / ПР", { t: "ПР в работе", num: true }, { t: "Сигналов вручную", num: true }, { t: "Массово", num: true },
      { t: "Само (AI/AO по Д22)", num: true }, { t: "Точек Д22", num: true }, { t: "Не норма", num: true }, { t: "Расхождений", num: true },
      { t: "Замечаний", num: true }, "Первая / последняя отметка"], rows, { empty: "Отметок нет" })}</div>
    <div class="card"><div class="title-row" style="margin-bottom:8px"><h2 style="margin:0;flex:1">Отметки по дням</h2>${selectHtml("f-who", "Все испытатели", who, list.map((p) => p.name))}</div>
      ${dayBars(mergeDays(chosen.flatMap((p) => p.rows.map(([, t]) => t))))}</div>`;
}

function pageStub(kind) {
  if (kind === "tasks") {
    return `<h1 class="title">Задачи</h1><p class="lead">Появятся на этапе 2 — вместе с внутренним сервером и вводом данных на портале.</p>
      <div class="card stub"><h2>Что будет</h2><ul><li>Задачи и план работ с исполнителями и сроками.</li><li>Срок сдачи ПР.</li><li>Справочник сотрудников с портала.</li></ul></div>
      <div class="card stub"><h2>Что видно уже сейчас</h2><ul><li>Кто ведёт ПР — ответственные в <a href="#/orders">«Распоряжениях»</a> и в карточке ПР.</li>
      <li>Кто и когда ставил отметки — <a href="#/analytics?tab=testers">«Аналитика» → «Испытатели»</a>.</li><li>Даты ЗИ и ПСИ — <a href="#/plan">«План работ»</a>.</li></ul></div>`;
  }
  return `<h1 class="title">ОТК</h1><p class="lead">Появится на этапе 2 — вместе с внутренним сервером и вводом данных на портале.</p>
    <div class="card stub"><h2>Что будет</h2><ul><li>Очередь осмотров ОТК.</li><li>Чек-листы: комплектность, маркировка, монтаж, внешний вид.</li><li>Повторный контроль и проверка устранения замечаний.</li></ul></div>
    <div class="card stub"><h2>Что видно уже сейчас</h2><ul><li>Замечания по маркировке и монтажу заводят испытатели в приложении:
      <a href="#/remarks?section=${encodeURIComponent("Маркировка")}">«Маркировка»</a>, <a href="#/remarks?section=${encodeURIComponent("Монтаж")}">«Монтаж»</a>.</li></ul></div>`;
}

// --------------------------------------------------------------------------- отрисовка

function render() {
  if (!DATA) return;
  const { parts, q } = parseRoute();
  const focus = document.activeElement && document.activeElement.id;
  const caret = focus && document.activeElement.selectionStart;
  const section = { "": "overview", orders: "orders", plan: "plan", tasks: "tasks", results: "results", otk: "otk", remarks: "remarks", analytics: "analytics" }[parts[0] || ""] || "overview";
  let html, order = null;
  if (section === "orders" && parts[1]) {
    order = findOrder(parts[1]);
    html = order ? pageOrder(order, parts[2] || "overview", q) : `<h1 class="title">ПР не найдено</h1><p class="lead">${esc(parts[1])} нет в сводке. <a href="#/orders">Все распоряжения</a></p>`;
  } else {
    html = { overview: pageOverview, orders: () => pageOrders(q), plan: () => pagePlan(q), tasks: () => pageStub("tasks"),
             results: pageResults, otk: () => pageStub("otk"), remarks: () => pageRemarks(q), analytics: () => pageAnalytics(q) }[section]();
  }
  const banner = DATA.generatedAt && (Date.now() - DATA.generatedAt) / 36e5 > STALE_HOURS
    ? `<div class="banner warn">Сводка собрана ${ago(DATA.generatedAt)} — приложение давно не публиковало данные.</div>` : "";
  $("main").innerHTML = banner + html + footer();
  renderNav(section);
  const sub = $("subbar");
  sub.hidden = !order;
  if (order) sub.innerHTML = `<b>${esc(order.order_no)}</b><span>${esc(order.object)}</span>`;
  document.title = (order ? order.order_no + " — " : "") + "Служба качества";
  $("panel-root").innerHTML = q.get("id") && (section === "remarks" || order) ? remarkPanel(q.get("id")) : "";
  if (focus && $(focus)) { const el = $(focus); el.focus(); if (caret != null && el.setSelectionRange) try { el.setSelectionRange(caret, caret); } catch (e) {} }
  closeMenu();
}

// фильтры: поиск — с задержкой, списки — сразу; адрес обновляется (прямая ссылка открывает то же)
let searchTimer = null;
document.addEventListener("input", (e) => {
  if (e.target.id === "f-q") { clearTimeout(searchTimer); const v = e.target.value; searchTimer = setTimeout(() => setQuery({ q: v, id: "" }), 200); }
});
document.addEventListener("change", (e) => {
  const map = { "f-stage": "stage", "f-order": "order", "f-section": "section", "f-status": "status", "f-owner": "owner", "f-who": "who" };
  if (map[e.target.id]) setQuery({ [map[e.target.id]]: e.target.value, id: "" });
});
document.addEventListener("click", (e) => {
  const copy = e.target.closest("[data-copy]");
  if (copy) {
    navigator.clipboard && navigator.clipboard.writeText(copy.dataset.copy).then(() => { copy.textContent = "Скопировано"; setTimeout(() => (copy.textContent = "Копировать"), 1500); },
      () => { const c = $("srv"); if (c) { const r = document.createRange(); r.selectNodeContents(c); getSelection().removeAllRanges(); getSelection().addRange(r); } });
    return;
  }
  if (e.target.closest("[data-close-panel]")) { setQuery({ id: "" }); return; }
  const row = e.target.closest("tr[data-href]");
  if (row && !e.target.closest("a, button, input, select")) location.hash = row.dataset.href;
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("panel-root").innerHTML) setQuery({ id: "" });
  if (e.key === "Escape") closeMenu();
});
window.addEventListener("hashchange", () => { render(); $("main").focus({ preventScroll: true }); window.scrollTo(0, 0); });

// меню на телефоне
function closeMenu() { $("nav").classList.remove("open"); $("scrim").classList.remove("open"); $("menu-btn").setAttribute("aria-expanded", "false"); }
$("menu-btn").addEventListener("click", () => {
  const open = !$("nav").classList.contains("open");
  $("nav").classList.toggle("open", open); $("scrim").classList.toggle("open", open); $("menu-btn").setAttribute("aria-expanded", String(open));
});
$("scrim").addEventListener("click", closeMenu);

// тема: сохранённая или как в системе; переключатель запоминается
function isDark() {
  const t = document.documentElement.dataset.theme;
  return t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
}
function themeIcon() {
  $("theme-btn").innerHTML = isDark()
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/></svg>';
  $("theme-btn").title = isDark() ? "Светлая тема" : "Тёмная тема";
}
$("theme-btn").addEventListener("click", () => {
  const next = isDark() ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
  themeIcon();
});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", themeIcon);

// --------------------------------------------------------------------------- вход, обновление, выход

function showLogin(message, kind) {
  $("app").hidden = true; $("login").hidden = false;
  const m = $("login-msg");
  m.hidden = !message; m.textContent = message || ""; m.className = `login-msg ${kind || "err"}`;
  $("password").focus();
}
function showApp() {
  $("login").hidden = true; $("app").hidden = false;
  $("stamp").textContent = DATA.generatedAt ? `сводка ${fmtDT(DATA.generatedAt)}` : "";
  $("stamp").title = DATA.by ? `Опубликовал: ${DATA.by}` : "";
  themeIcon();
  render();
}

async function openSite(password, fromForm) {
  const btn = $("login-btn");
  btn.disabled = true; btn.textContent = "Расшифровываем…";
  try {
    const data = await loadData(password);
    if (!data || !Array.isArray(data.orders)) throw new LoadError("broken", "Файл сводки другого формата — опубликуйте её из приложения заново.");
    try { sessionStorage.setItem(PW_KEY, password); } catch (e) {}
    prepare(data);
    showApp();
  } catch (e) {
    if (e.kind === "password") { try { sessionStorage.removeItem(PW_KEY); } catch (x) {} }
    showLogin(e.kind === "password" && !fromForm ? "Пароль сменился — введите новый." : e.message, e.kind === "nodata" ? "info" : "err");
  } finally {
    btn.disabled = false; btn.textContent = "Войти";
  }
}

$("login-form").addEventListener("submit", (e) => { e.preventDefault(); openSite($("password").value, true); });
$("logout-btn").addEventListener("click", () => {
  try { sessionStorage.removeItem(PW_KEY); } catch (e) {}
  DATA = null; ORDERS = []; REMARKS = []; $("password").value = ""; $("panel-root").innerHTML = "";
  showLogin("");
});
$("refresh-btn").addEventListener("click", async () => {
  let pw = null;
  try { pw = sessionStorage.getItem(PW_KEY); } catch (e) {}
  if (!pw) return showLogin("");
  const b = $("refresh-btn"); b.disabled = true;
  try { const data = await loadData(pw); prepare(data); showApp(); }
  catch (e) { if (e.kind === "password") { openSite(pw, false); } else alert(e.message); }
  finally { b.disabled = false; }
});

(function start() {
  if (!window.crypto || !crypto.subtle) { showLogin("Браузер не поддерживает расшифровку (нужен https и современный браузер)."); return; }
  let pw = null;
  try { pw = sessionStorage.getItem(PW_KEY); } catch (e) {}
  if (pw) openSite(pw, false); else showLogin("");
})();
