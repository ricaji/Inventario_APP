/* Inventario APP - usuarios y sesión en línea (Firebase Authentication + Cloud Firestore).
 *
 * - La contraseña la guarda y valida Firebase Authentication (nunca se guarda aquí).
 * - Los perfiles (rol, nombres, estado) viven en Firestore y se ven desde cualquier navegador.
 * - Las reglas de Firestore (ver firestore.rules) hacen cumplir los permisos en el servidor:
 *   solo Administrador y Soporte gestionan usuarios y Soporte no toca Administradores.
 * - Inicio de sesión por nombre de usuario: /logins/{usuario} guarda el correo y los intentos fallidos.
 */
(function (global) {
  'use strict';

  var CONFIG = {
    apiKey: 'AIzaSyBb7gEOfv7u4TWzv5NCuhNpNrLv6usvMaU',
    authDomain: 'inventario-app-c749f.firebaseapp.com',
    projectId: 'inventario-app-c749f',
    storageBucket: 'inventario-app-c749f.firebasestorage.app',
    messagingSenderId: '7002697988',
    appId: '1:7002697988:web:4b12f3117d5ff2a32ba051'
  };
  var ROLES = ['Administrador', 'Soporte', 'Contratista', 'Vinculado'];
  var MAX_INTENTOS = 3, BLOQUEO_MIN = 15;
  var RE_USER = /^[A-Za-z0-9._-]{3,30}$/, RE_MAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  var MSG_CLAVE = 'La contraseña debe tener al menos 6 caracteres.';
  var MSG_DESHAB = 'Este usuario está deshabilitado. Comuníquese con un Administrador.';
  var MSG_SOPORTE = 'El rol Soporte no puede crear ni modificar usuarios Administradores.';
  var MSG_MALA = 'Usuario o contraseña incorrectos.';

  var auth = null, db = null, cur = null;

  function low(s) { return String(s || '').trim().toLowerCase(); }
  function validClave(c) { return typeof c === 'string' && c.length >= 6 && c.length <= 100; }
  function ts(ms) { return firebase.firestore.Timestamp.fromMillis(ms); }

  function iniciar() {
    if (auth) return;
    if (!global.firebase) throw new Error('No se pudo cargar Firebase. Revise su conexión a internet.');
    if (!firebase.apps.length) firebase.initializeApp(CONFIG);
    auth = firebase.auth(); db = firebase.firestore();
    auth.languageCode = 'es';
  }

  function msgError(e) {
    var c = (e && e.code) || '';
    if (c === 'permission-denied') return 'No tiene permiso para realizar esta acción.';
    if (c === 'auth/email-already-in-use') return 'Ese correo ya está registrado.';
    if (c === 'auth/weak-password') return MSG_CLAVE;
    if (c === 'auth/invalid-email') return 'Correo electrónico inválido.';
    if (c === 'auth/too-many-requests') return 'Demasiados intentos. Espere unos minutos o restablezca la contraseña.';
    if (c === 'auth/network-request-failed' || c === 'unavailable') return 'Sin conexión con el servidor. Revise su internet.';
    if (c === 'auth/requires-recent-login') return 'Por seguridad, vuelva a iniciar sesión.';
    return (e && e.message) || 'Ocurrió un error inesperado.';
  }
  function safe(fn) {
    return async function () {
      try { iniciar(); return await fn.apply(null, arguments); }
      catch (e) { return { error: msgError(e) }; }
    };
  }
  function esCredencial(e) {
    var c = (e && e.code) || '';
    return c === 'auth/invalid-credential' || c === 'auth/wrong-password' || c === 'auth/user-not-found' || c === 'auth/invalid-login-credentials';
  }

  function perfilPub(uid, d) {
    return {
      uid: uid, usuario: d.usuario, nombres: d.nombres || d.nombre || '', apellidos: d.apellidos || '',
      nombre: d.nombre || ((d.nombres || '') + ' ' + (d.apellidos || '')).trim(),
      correo: d.correo, rol: d.rol, deshabilitado: !!d.deshabilitado, porDefecto: !!d.porDefecto
    };
  }
  function bloqueadoAhora(l) {
    return !!(l && l.bloqueadoHasta && l.bloqueadoHasta.toMillis && l.bloqueadoHasta.toMillis() > Date.now());
  }
  async function leerLogin(usr) {
    var s = await db.collection('logins').doc(usr).get();
    return s.exists ? s.data() : null;
  }
  async function leerPerfil(uid) {
    var s = await db.collection('usuarios').doc(uid).get();
    return s.exists ? perfilPub(uid, s.data()) : null;
  }
  // Devuelve { login, perfil, uid } del usuario indicado, o null.
  async function buscar(usuario) {
    var usr = low(usuario), l = await leerLogin(usr);
    if (!l) return null;
    var p = await leerPerfil(l.uid);
    return p ? { login: l, perfil: p, uid: l.uid, usr: usr } : null;
  }

  /* ---------- sesión ---------- */
  var listo = null;
  function init() {
    if (listo) return listo;
    listo = (async function () {
      try {
        iniciar();
        await auth.setPersistence(firebase.auth.Auth.Persistence.SESSION);
        var u = await new Promise(function (res) { var off = auth.onAuthStateChanged(function (x) { off(); res(x); }); });
        if (u) {
          var p = null;
          try { p = await leerPerfil(u.uid); } catch (e) { p = null; }
          if (!p || p.deshabilitado) { await auth.signOut(); cur = null; } else cur = p;
        }
        return { ok: true };
      } catch (e) { return { error: msgError(e) }; }
    })();
    return listo;
  }
  function current() { return cur; }
  async function logout() {
    cur = null;
    try { iniciar(); await auth.signOut(); } catch (e) { /* nada */ }
  }

  async function registrarFallo(usr, l) {
    var n = ((l && l.intentos) || 0) + 1, cambios = { intentos: n };
    if (n >= MAX_INTENTOS) cambios.bloqueadoHasta = ts(Date.now() + BLOQUEO_MIN * 60000);
    try { await db.collection('logins').doc(usr).update(cambios); } catch (e) { /* el servidor igual limita con su propio control */ }
    return n;
  }
  async function entrar(usr, clave) {
    var l = await leerLogin(usr);
    if (!l) return { error: MSG_MALA };
    if (bloqueadoAhora(l)) return { error: 'Cuenta bloqueada tras 3 intentos fallidos. Restablezca la contraseña con su correo o pida a un Administrador o Soporte que la desbloquee.', bloqueado: true };
    var cred;
    try { cred = await auth.signInWithEmailAndPassword(l.correo, clave); }
    catch (e) {
      if (!esCredencial(e)) throw e;
      var n = await registrarFallo(usr, l);
      if (n >= MAX_INTENTOS) return { error: 'Cuenta bloqueada tras 3 intentos fallidos. Restablezca la contraseña con su correo o pida a un Administrador o Soporte que la desbloquee.', bloqueado: true };
      return { error: MSG_MALA + ' Intentos restantes: ' + (MAX_INTENTOS - n) + '.' };
    }
    var p = null;
    try { p = await leerPerfil(cred.user.uid); } catch (e) { p = null; }
    if (!p) { await auth.signOut(); return { error: 'Su cuenta no tiene perfil asignado. Comuníquese con un Administrador.' }; }
    if (p.deshabilitado) { await auth.signOut(); return { error: MSG_DESHAB }; }
    if (l.intentos || l.bloqueadoHasta) {
      try { await db.collection('logins').doc(usr).update({ intentos: 0, bloqueadoHasta: firebase.firestore.FieldValue.delete() }); } catch (e) { /* no crítico */ }
    }
    return { ok: true, user: p, cred: cred };
  }

  var login = safe(async function (usuario, clave) {
    var usr = low(usuario);
    if (!usr || !clave) return { error: 'Escriba su usuario y contraseña.' };
    var r = await entrar(usr, String(clave));
    if (!r.ok) return r;
    cur = r.user;
    return { ok: true, user: cur };
  });

  // Envía el correo oficial de Firebase para elegir una nueva contraseña.
  var enviarRestablecer = safe(async function (correo) {
    var mail = String(correo || '').trim();
    if (!RE_MAIL.test(mail)) return { error: 'Escriba un correo electrónico válido.' };
    try { await auth.sendPasswordResetEmail(mail); }
    catch (e) { if ((e && e.code) !== 'auth/user-not-found') throw e; }
    return { ok: true, correo: mail };
  });

  var cambiarClave = safe(async function (usuario, actual, nueva) {
    var usr = low(usuario);
    if (!usr || !actual) return { error: 'Escriba su usuario y su contraseña actual.' };
    if (!validClave(nueva)) return { error: MSG_CLAVE };
    var r = await entrar(usr, String(actual));
    if (!r.ok) return r;
    await r.cred.user.updatePassword(nueva);
    if (r.user.porDefecto) {
      try { await db.collection('usuarios').doc(r.user.uid).update({ porDefecto: false }); } catch (e) { /* no crítico */ }
    }
    await auth.signOut(); cur = null;
    return { ok: true };
  });

  /* ---------- gestión de usuarios (Administrador y Soporte) ---------- */
  function exigirGestor() {
    if (!cur || (cur.rol !== 'Administrador' && cur.rol !== 'Soporte')) throw new Error('Acceso solo para Administradores y Soporte.');
    return cur;
  }
  function soporteNoToca(yo, rolDestino) { return yo.rol === 'Soporte' && rolDestino === 'Administrador'; }

  var listar = safe(async function () {
    exigirGestor();
    var res = await Promise.all([db.collection('usuarios').get(), db.collection('logins').get()]);
    var bloqueos = {};
    res[1].forEach(function (d) { bloqueos[d.id] = bloqueadoAhora(d.data()); });
    var users = [];
    res[0].forEach(function (d) {
      var p = perfilPub(d.id, d.data());
      p.bloqueado = !!bloqueos[low(p.usuario)];
      users.push(p);
    });
    users.sort(function (a, b) { return a.usuario < b.usuario ? -1 : 1; });
    return { ok: true, users: users };
  });

  var crear = safe(async function (d) {
    var yo = exigirGestor();
    var usr = String(d.usuario || '').trim(), mail = String(d.correo || '').trim();
    var nms = String(d.nombres || '').trim(), aps = String(d.apellidos || '').trim();
    if (!RE_USER.test(usr)) return { error: 'Usuario: de 3 a 30 caracteres (letras, números, . _ -).' };
    if (!nms) return { error: 'Escriba los nombres.' };
    if (!aps) return { error: 'Escriba los apellidos.' };
    if (!RE_MAIL.test(mail)) return { error: 'Correo electrónico inválido.' };
    if (ROLES.indexOf(d.rol) < 0) return { error: 'Seleccione un rol válido.' };
    if (soporteNoToca(yo, d.rol)) return { error: MSG_SOPORTE };
    if (!validClave(d.clave)) return { error: MSG_CLAVE };
    var key = low(usr);
    if (await leerLogin(key)) return { error: 'Ese usuario ya existe.' };

    // La cuenta se crea con una segunda instancia para no cerrar la sesión de quien la crea.
    var sec = firebase.apps.filter(function (a) { return a.name === 'sec'; })[0] || firebase.initializeApp(CONFIG, 'sec');
    var cred = await sec.auth().createUserWithEmailAndPassword(mail, d.clave);
    var uid = cred.user.uid;
    await sec.auth().signOut();

    var batch = db.batch();
    batch.set(db.collection('usuarios').doc(uid), {
      usuario: usr, nombres: nms, apellidos: aps, nombre: nms + ' ' + aps, correo: mail, rol: d.rol,
      deshabilitado: false, porDefecto: false
    });
    batch.set(db.collection('logins').doc(key), { uid: uid, correo: mail, intentos: 0 });
    await batch.commit();
    return { ok: true };
  });

  var actualizar = safe(async function (usuario, d) {
    var yo = exigirGestor();
    var t = await buscar(usuario);
    if (!t) return { error: 'Usuario no encontrado.' };
    if (soporteNoToca(yo, t.perfil.rol)) return { error: MSG_SOPORTE };
    var cambios = {};
    if (d.nombres !== undefined || d.apellidos !== undefined) {
      var nms = String(d.nombres !== undefined ? d.nombres : t.perfil.nombres).trim();
      var aps = String(d.apellidos !== undefined ? d.apellidos : t.perfil.apellidos).trim();
      if (!nms) return { error: 'Escriba los nombres.' };
      if (!aps) return { error: 'Escriba los apellidos.' };
      cambios.nombres = nms; cambios.apellidos = aps; cambios.nombre = nms + ' ' + aps;
    }
    if (d.rol !== undefined) {
      if (ROLES.indexOf(d.rol) < 0) return { error: 'Seleccione un rol válido.' };
      if (soporteNoToca(yo, d.rol)) return { error: MSG_SOPORTE };
      if (t.usr === 'admin' && d.rol !== 'Administrador') return { error: 'El usuario admin siempre es Administrador.' };
      cambios.rol = d.rol;
    }
    if (Object.keys(cambios).length) await db.collection('usuarios').doc(t.uid).update(cambios);
    return { ok: true };
  });

  var desbloquear = safe(async function (usuario) {
    var yo = exigirGestor();
    var t = await buscar(usuario);
    if (!t) return { error: 'Usuario no encontrado.' };
    if (soporteNoToca(yo, t.perfil.rol)) return { error: MSG_SOPORTE };
    await db.collection('logins').doc(t.usr).update({ intentos: 0, bloqueadoHasta: firebase.firestore.FieldValue.delete() });
    return { ok: true };
  });

  var habilitar = safe(async function (usuario, habilitado) {
    var yo = exigirGestor();
    var t = await buscar(usuario);
    if (!t) return { error: 'Usuario no encontrado.' };
    if (soporteNoToca(yo, t.perfil.rol)) return { error: MSG_SOPORTE };
    if (!habilitado) {
      if (t.usr === 'admin') return { error: 'El usuario admin no se puede deshabilitar.' };
      if (t.uid === yo.uid) return { error: 'No puede deshabilitar su propio usuario.' };
    }
    await db.collection('usuarios').doc(t.uid).update({ deshabilitado: !habilitado });
    return { ok: true };
  });

  // Un Administrador o Soporte envía al usuario el correo para que elija su nueva contraseña.
  var enviarRestablecerA = safe(async function (usuario) {
    var yo = exigirGestor();
    var t = await buscar(usuario);
    if (!t) return { error: 'Usuario no encontrado.' };
    if (soporteNoToca(yo, t.perfil.rol)) return { error: MSG_SOPORTE };
    await auth.sendPasswordResetEmail(t.perfil.correo);
    return { ok: true, correo: t.perfil.correo };
  });

  global.App = {
    ROLES: ROLES, init: init, current: current, logout: logout, login: login,
    enviarRestablecer: enviarRestablecer, cambiarClave: cambiarClave,
    listar: listar, crear: crear, actualizar: actualizar, desbloquear: desbloquear, habilitar: habilitar,
    enviarRestablecerA: enviarRestablecerA
  };
})(window);
