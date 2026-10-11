/* Inventario APP - usuarios, sesión y contraseñas.
 *
 * IMPORTANTE: esta versión guarda todo en el navegador (localStorage). Sirve para
 * armar y probar la interfaz, pero NO es seguridad real: cualquiera con acceso al
 * navegador puede leer o alterar los datos. Cada navegador tiene sus propios usuarios.
 * Para uso real hay que mover estas funciones a un servidor.
 */
(function (global) {
  'use strict';

  var KEY = 'ia_usuarios', RESET = 'ia_reset', SES = 'ia_sesion';
  var ROLES = ['Administrador', 'Soporte', 'Contratista', 'Vinculado'];
  var MAX_INTENTOS = 3, ITER = 100000, RESET_MIN = 15;

  // Usuario principal. Solo se guarda el hash de la clave inicial, no la clave.
  var SEED = {
    usuario: 'admin', nombre: 'Administrador principal', correo: 'admin@empresa.com',
    rol: 'Administrador',
    salt: '6bf863f0ba0832d47e03490ae0938973',
    hash: 'c62191bcb802838c847b438051c3cf6b079504806f833549b11602ea4c21469e'
  };

  /* ---------- almacenamiento (con respaldo en memoria si el navegador lo bloquea) ---------- */
  var mem = {};
  function lget(k) { try { return localStorage.getItem(k); } catch (e) { return mem[k] || null; } }
  function lset(k, v) { try { localStorage.setItem(k, v); } catch (e) { mem[k] = v; } }
  function ldel(k) { try { localStorage.removeItem(k); } catch (e) { delete mem[k]; } }
  function sget(k) { try { return sessionStorage.getItem(k); } catch (e) { return mem['s_' + k] || null; } }
  function sset(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { mem['s_' + k] = v; } }
  function sdel(k) { try { sessionStorage.removeItem(k); } catch (e) { delete mem['s_' + k]; } }

  function readUsers() {
    try { var a = JSON.parse(lget(KEY)); return Array.isArray(a) ? a : []; } catch (e) { return []; }
  }
  function writeUsers(a) { lset(KEY, JSON.stringify(a)); }

  /* ---------- cifrado ---------- */
  var enc = new TextEncoder();
  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  function randHex(bytes) {
    var a = new Uint8Array(bytes); crypto.getRandomValues(a); return hex(a);
  }
  async function derive(texto, salt) {
    if (!global.crypto || !crypto.subtle) throw new Error('Este navegador no puede cifrar contraseñas (se necesita https o localhost).');
    var key = await crypto.subtle.importKey('raw', enc.encode(texto), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: ITER }, key, 256);
    return hex(bits);
  }
  function code6() {
    var a = new Uint32Array(1); crypto.getRandomValues(a); return String(100000 + (a[0] % 900000));
  }

  /* ---------- utilidades ---------- */
  function low(s) { return String(s || '').trim().toLowerCase(); }
  function pub(u) {
    return { usuario: u.usuario, nombre: u.nombre, correo: u.correo, rol: u.rol, bloqueado: !!u.bloqueado, deshabilitado: !!u.deshabilitado, porDefecto: !!u.porDefecto };
  }
  function findUser(us, nombre) { return us.filter(function (u) { return low(u.usuario) === low(nombre); })[0]; }
  function findMail(us, mail) { return us.filter(function (u) { return low(u.correo) === low(mail); })[0]; }
  function validClave(c) { return typeof c === 'string' && c.length >= 6 && c.length <= 100; }
  var MSG_DESHAB = 'Este usuario está deshabilitado. Comuníquese con un Administrador.';
  var MSG_CLAVE = 'La contraseña debe tener al menos 6 caracteres.';
  var RE_USER = /^[A-Za-z0-9._-]{3,30}$/, RE_MAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

  function safe(fn) {
    return async function () {
      try { return await fn.apply(null, arguments); }
      catch (e) { return { error: (e && e.message) || 'Ocurrió un error inesperado.' }; }
    };
  }

  // Suma un intento fallido; bloquea al llegar a 3
  function fallo(us, u) {
    u.intentos = (u.intentos || 0) + 1;
    if (u.intentos >= MAX_INTENTOS) u.bloqueado = true;
    writeUsers(us);
    if (u.bloqueado) {
      return { error: 'Cuenta bloqueada tras 3 intentos fallidos. Restablezca la contraseña con su correo o pida a un Administrador que la desbloquee.', bloqueado: true };
    }
    return { error: 'Usuario o contraseña incorrectos. Intentos restantes: ' + (MAX_INTENTOS - u.intentos) + '.' };
  }

  /* ---------- sesión ---------- */
  var init = safe(async function () {
    var us = readUsers();
    if (!us.some(function (u) { return u.usuario === 'admin'; })) {
      us.unshift(Object.assign({}, SEED, { intentos: 0, bloqueado: false, porDefecto: true }));
      writeUsers(us);
    }
    return { ok: true };
  });

  function current() {
    var n = sget(SES);
    if (!n) return null;
    var u = findUser(readUsers(), n);
    return (u && !u.bloqueado && !u.deshabilitado) ? pub(u) : null;
  }
  function logout() { sdel(SES); }

  var login = safe(async function (usuario, clave) {
    var us = readUsers(), u = findUser(us, usuario);
    if (!u) return { error: 'Usuario o contraseña incorrectos.' };
    if (u.deshabilitado) return { error: MSG_DESHAB };
    if (u.bloqueado) return { error: 'Cuenta bloqueada por 3 intentos fallidos. Restablezca la contraseña con su correo o pida a un Administrador que la desbloquee.', bloqueado: true };
    if (await derive(String(clave || ''), u.salt) !== u.hash) return fallo(us, u);
    u.intentos = 0; writeUsers(us); sset(SES, u.usuario);
    return { ok: true, user: pub(u) };
  });

  /* ---------- restablecer y cambiar contraseña ---------- */
  // Sin servidor de correo no se puede enviar un email: el código se devuelve para mostrarlo en pantalla.
  var pedirCodigo = safe(async function (correo) {
    var us = readUsers(), u = findMail(us, correo);
    if (!u) return { error: 'Ese correo no está registrado.' };
    if (u.deshabilitado) return { error: MSG_DESHAB };
    var code = code6();
    lset(RESET, JSON.stringify({ usuario: u.usuario, h: await derive(code, u.salt), exp: Date.now() + RESET_MIN * 60000, n: 0 }));
    return { ok: true, codigo: code, correo: u.correo, minutos: RESET_MIN };
  });

  var restablecer = safe(async function (correo, codigo, nueva) {
    var us = readUsers(), u = findMail(us, correo), bad = { error: 'Código inválido o vencido.' };
    var r; try { r = JSON.parse(lget(RESET)); } catch (e) { r = null; }
    if (u && u.deshabilitado) return { error: MSG_DESHAB };
    if (!u || !r || r.usuario !== u.usuario || Date.now() > r.exp || r.n >= 5) return bad;
    if (await derive(String(codigo || '').trim(), u.salt) !== r.h) { r.n += 1; lset(RESET, JSON.stringify(r)); return bad; }
    if (!validClave(nueva)) return { error: MSG_CLAVE };
    u.salt = randHex(16); u.hash = await derive(nueva, u.salt);
    u.intentos = 0; u.bloqueado = false; u.porDefecto = false;
    writeUsers(us); ldel(RESET);
    return { ok: true };
  });

  var cambiarClave = safe(async function (usuario, actual, nueva) {
    var us = readUsers(), u = findUser(us, usuario);
    if (!u) return { error: 'Usuario o contraseña actual incorrectos.' };
    if (u.deshabilitado) return { error: MSG_DESHAB };
    if (u.bloqueado) return { error: 'Cuenta bloqueada. Restablezca la contraseña con su correo.', bloqueado: true };
    if (await derive(String(actual || ''), u.salt) !== u.hash) return fallo(us, u);
    if (!validClave(nueva)) return { error: MSG_CLAVE };
    u.salt = randHex(16); u.hash = await derive(nueva, u.salt);
    u.intentos = 0; u.porDefecto = false;
    writeUsers(us);
    return { ok: true };
  });

  /* ---------- administración de usuarios (solo Administrador) ---------- */
  function exigirAdmin() {
    var c = current();
    if (!c || c.rol !== 'Administrador') throw new Error('Acceso solo para Administradores.');
    return c;
  }

  var listar = safe(async function () {
    exigirAdmin();
    return { ok: true, users: readUsers().map(pub) };
  });

  var crear = safe(async function (d) {
    exigirAdmin();
    var us = readUsers(), usr = String(d.usuario || '').trim(), mail = String(d.correo || '').trim(), nom = String(d.nombre || '').trim();
    if (!RE_USER.test(usr)) return { error: 'Usuario: de 3 a 30 caracteres (letras, números, . _ -).' };
    if (!nom) return { error: 'Escriba el nombre completo.' };
    if (!RE_MAIL.test(mail)) return { error: 'Correo electrónico inválido.' };
    if (ROLES.indexOf(d.rol) < 0) return { error: 'Seleccione un rol válido.' };
    if (!validClave(d.clave)) return { error: MSG_CLAVE };
    if (findUser(us, usr)) return { error: 'Ese usuario ya existe.' };
    if (findMail(us, mail)) return { error: 'Ese correo ya está registrado.' };
    var salt = randHex(16);
    us.push({ usuario: usr, nombre: nom, correo: mail, rol: d.rol, salt: salt, hash: await derive(d.clave, salt), intentos: 0, bloqueado: false, deshabilitado: false, porDefecto: false });
    writeUsers(us);
    return { ok: true };
  });

  var actualizar = safe(async function (usuario, d) {
    exigirAdmin();
    var us = readUsers(), u = findUser(us, usuario);
    if (!u) return { error: 'Usuario no encontrado.' };
    if (d.nombre !== undefined) {
      if (!String(d.nombre).trim()) return { error: 'Escriba el nombre completo.' };
      u.nombre = String(d.nombre).trim();
    }
    if (d.correo !== undefined) {
      var mail = String(d.correo).trim(), otro = findMail(us, mail);
      if (!RE_MAIL.test(mail)) return { error: 'Correo electrónico inválido.' };
      if (otro && otro !== u) return { error: 'Ese correo ya está registrado.' };
      u.correo = mail;
    }
    if (d.rol !== undefined) {
      if (ROLES.indexOf(d.rol) < 0) return { error: 'Seleccione un rol válido.' };
      if (u.usuario === 'admin' && d.rol !== 'Administrador') return { error: 'El usuario admin siempre es Administrador.' };
      u.rol = d.rol;
    }
    if (d.clave) {
      if (!validClave(d.clave)) return { error: MSG_CLAVE };
      u.salt = randHex(16); u.hash = await derive(d.clave, u.salt); u.porDefecto = false;
    }
    writeUsers(us);
    return { ok: true };
  });

  var desbloquear = safe(async function (usuario) {
    exigirAdmin();
    var us = readUsers(), u = findUser(us, usuario);
    if (!u) return { error: 'Usuario no encontrado.' };
    u.bloqueado = false; u.intentos = 0; writeUsers(us);
    return { ok: true };
  });

  var habilitar = safe(async function (usuario, habilitado) {
    var yo = exigirAdmin();
    var us = readUsers(), u = findUser(us, usuario);
    if (!u) return { error: 'Usuario no encontrado.' };
    if (!habilitado) {
      if (u.usuario === 'admin') return { error: 'El usuario admin no se puede deshabilitar.' };
      if (u.usuario === yo.usuario) return { error: 'No puede deshabilitar su propio usuario.' };
    }
    u.deshabilitado = !habilitado; writeUsers(us);
    return { ok: true };
  });

  global.App = {
    ROLES: ROLES, init: init, current: current, logout: logout, login: login,
    pedirCodigo: pedirCodigo, restablecer: restablecer, cambiarClave: cambiarClave,
    listar: listar, crear: crear, actualizar: actualizar, desbloquear: desbloquear, habilitar: habilitar
  };
})(window);
