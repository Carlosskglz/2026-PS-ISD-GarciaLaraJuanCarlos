// La aplicación de la demo. server.js la arranca; las pruebas la arrancan con otras configuraciones.
const path = require('path');
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { crearModeloUsuarios } = require('./modelos/usuarios.modelo');
const { crearModeloTokens } = require('./modelos/tokens.modelo');

const NOMBRE_COOKIE = 'connect.sid';

// Regresa TODAS las sesiones del almacén (sirve para la tabla "4 · Lo que guarda el servidor").
// MemoryStore y MySQLStore usan callback; se soportan también las versiones que regresan promesa.
function todasLasSesiones(almacen) {
  return new Promise((resolve, reject) => {
    const promesa = almacen.all((error, sesiones) => (error ? reject(error) : resolve(sesiones)));
    if (promesa && typeof promesa.then === 'function') promesa.then(resolve, reject);
  });
}

function crearApp(config, pool) {
  const app = express();
  app.use(express.json());
  const usuarios = crearModeloUsuarios(pool);
  const tokens = crearModeloTokens(pool);

  // ---------- PASO 1 · La sesión y su almacén ----------
  // 'memoria' → MemoryStore (se pierde al reiniciar) | 'mysql' → tabla sessions (sobrevive al reinicio)
  const almacen =
    config.almacen === 'memoria'
      ? new session.MemoryStore()
      : new MySQLStore({ createDatabaseTable: false, clearExpired: false }, pool);
  app.locals.almacen = almacen;

  app.use(
    session({
      name: NOMBRE_COOKIE,
      secret: process.env.SESSION_SECRET || 'secreto-solo-para-la-demo',
      store: almacen,
      resave: false,
      saveUninitialized: false, // no crea sesión ni cookie hasta que haya algo que guardar
      rolling: config.rolling, // true: cada respuesta renueva el Set-Cookie (vence por inactividad)
      cookie: {
        maxAge: config.maxAgeMs,
        httpOnly: config.httpOnly,
        sameSite: config.sameSite,
        secure: false, // en un servidor real con HTTPS va en true
      },
    })
  );

  // Versión corta del id para mostrarla en pantalla (nunca se muestra completo).
  const idCorto = (id) => (id ? `${id.slice(0, 8)}...` : null);

  // ---------- PASO 5 · El servidor decide cuándo vence ----------
  // rolling:true → cuenta desde el último uso | rolling:false → cuenta desde que se creó
  function vencida(sesion) {
    const desde = config.rolling ? sesion.ultimoUso : sesion.creada;
    return Date.now() - desde > config.maxAgeMs;
  }

  // ---------- PASO 1 · 401: "no sé quién eres" ----------
  function requiereSesion(req, res, next) {
    if (req.session.usuario && vencida(req.session)) {
      return req.session.destroy(() => {
        res.clearCookie(NOMBRE_COOKIE);
        res.status(401).json({ error: '401 · Tu sesión venció. Vuelve a iniciar sesión.' });
      });
    }
    if (!req.session.usuario) {
      return res.status(401).json({ error: '401 · No has iniciado sesión.' });
    }
    req.session.ultimoUso = Date.now();
    next();
  }

  // ---------- PASO 3 · 403: "sé quién eres, pero no puedes" ----------
  function requiereRol(rol) {
    return (req, res, next) => {
      if (req.session.usuario.rol !== rol) {
        return res.status(403).json({
          error: `403 · Eres ${req.session.usuario.usuario} (${req.session.usuario.rol}), pero esta ruta es solo para ${rol}.`,
        });
      }
      next();
    };
  }

  // ---------- Rutas ----------
  app.get('/api/config', (req, res) => res.json(config));

  // Crea una sesión SIN usuario (sirve para el paso 7: fijación de sesión).
  app.post('/api/visita', (req, res) => {
    req.session.visitas = (req.session.visitas || 0) + 1;
    res.json({ visitas: req.session.visitas, sesion: idCorto(req.sessionID) });
  });

  // ---------- PASO 2 · Iniciar sesión ----------
  app.post('/api/login', async (req, res, next) => {
    try {
      const { usuario, contrasena } = req.body || {};
      const datos = await usuarios.verificar(usuario, contrasena);
      if (!datos) return res.status(401).json({ error: '401 · Usuario o contraseña incorrectos.' });

      const antes = req.session.visitas !== undefined ? idCorto(req.sessionID) : null;
      const visitas = req.session.visitas || 0;

      const guardar = () => {
        req.session.usuario = datos; // { id, usuario, nombre, rol } (sin el hash)
        req.session.visitas = visitas;
        req.session.creada = Date.now();
        req.session.ultimoUso = Date.now();
        req.session.save((error) => {
          if (error) return next(error);
          res.json({ usuario: datos, sesionAntes: antes, sesionDespues: idCorto(req.sessionID) });
        });
      };

      // ---------- PASO 7 · Contra la fijación: id NUEVO al iniciar sesión ----------
      if (config.regenerarAlEntrar) {
        req.session.regenerate((error) => (error ? next(error) : guardar()));
      } else {
        guardar();
      }
    } catch (error) {
      next(error);
    }
  });

  // ---------- PASO 2 · Cerrar sesión: se destruye en el servidor ----------
  app.post('/api/logout', (req, res, next) => {
    req.session.destroy((error) => {
      if (error) return next(error);
      res.clearCookie(NOMBRE_COOKIE);
      res.json({ mensaje: 'Sesión cerrada' });
    });
  });

  app.get('/api/sesion', requiereSesion, (req, res) => {
    const desde = config.rolling ? req.session.ultimoUso : req.session.creada;
    res.json({
      usuario: req.session.usuario,
      sesion: idCorto(req.sessionID),
      expiraEnSegundos: Math.max(0, Math.round((desde + config.maxAgeMs - Date.now()) / 1000)),
    });
  });

  app.get('/api/perfil', requiereSesion, (req, res) => {
    req.session.visitas = (req.session.visitas || 0) + 1;
    res.json({
      mensaje: `Hola ${req.session.usuario.nombre}`,
      rol: req.session.usuario.rol,
      visitas: req.session.visitas,
    });
  });

  // Primero requiereSesion (¿quién eres? → 401) y luego requiereRol (¿puedes? → 403).
  app.get('/api/admin/reporte', requiereSesion, requiereRol('admin'), (req, res) => {
    res.json({ reporte: 'Talleres: 3 · Alumnos inscritos: 120' });
  });

  // Solo para la clase: un servidor real NUNCA expone esto.
  app.get('/api/diagnostico/sesiones', async (req, res, next) => {
    try {
      const sesiones = await todasLasSesiones(almacen);
      const lista = Object.entries(sesiones || {}).map(([id, s]) => ({
        sesion: idCorto(id),
        esLaTuya: id === req.sessionID,
        usuario: s.usuario ? s.usuario.usuario : '(sin iniciar sesión)',
        visitas: s.visitas || 0,
        expira: s.cookie && s.cookie.expires,
      }));
      res.json({ almacen: config.almacen, sesiones: lista });
    } catch (error) {
      next(error);
    }
  });

  // =====================================================================
  // JWT (semana 13): el token lleva los datos DENTRO y el servidor no guarda sesión.
  // =====================================================================
  const SECRETO_JWT = process.env.JWT_SECRET || 'secreto-jwt-solo-para-la-demo';

  // Crea el token: datos (payload) + vencimiento + id único (jti), firmado con HS256.
  function firmarToken(usuario) {
    return jwt.sign(
      { sub: String(usuario.id), usuario: usuario.usuario, nombre: usuario.nombre, rol: usuario.rol },
      SECRETO_JWT,
      { algorithm: 'HS256', expiresIn: config.jwtExpiraSeg, jwtid: crypto.randomUUID() }
    );
  }

  // Middleware: lee "Authorization: Bearer <token>", valida firma y vencimiento y revisa la lista negra.
  async function requiereJWT(req, res, next) {
    const encabezado = req.headers.authorization || '';
    if (!encabezado.startsWith('Bearer ')) {
      return res.status(401).json({ error: '401 · Falta el token (encabezado Authorization: Bearer ...).' });
    }
    const token = encabezado.slice('Bearer '.length).trim();

    let datos;
    try {
      datos = jwt.verify(token, SECRETO_JWT, { algorithms: ['HS256'] });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: '401 · El token expiró. Renuévalo o vuelve a iniciar sesión.' });
      }
      return res.status(401).json({ error: '401 · Token inválido (firma o formato incorrectos).' });
    }

    try {
      if (config.jwtRevocar && (await tokens.estaRevocado(datos.jti))) {
        return res.status(401).json({ error: '401 · Token revocado: ya se cerró esa sesión (está en la lista negra).' });
      }
    } catch (error) {
      return next(error);
    }

    req.jwt = datos;
    next();
  }

  // Igual que requiereRol, pero leyendo el rol que viene DENTRO del token.
  function requiereRolJWT(rol) {
    return (req, res, next) => {
      if (req.jwt.rol !== rol) {
        return res.status(403).json({
          error: `403 · Eres ${req.jwt.usuario} (${req.jwt.rol}), pero esta ruta es solo para ${rol}.`,
        });
      }
      next();
    };
  }

  app.post('/api/jwt/login', async (req, res, next) => {
    try {
      const { usuario, contrasena } = req.body || {};
      const datos = await usuarios.verificar(usuario, contrasena);
      if (!datos) return res.status(401).json({ error: '401 · Usuario o contraseña incorrectos.' });
      res.json({ token: firmarToken(datos), usuario: datos });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/jwt/perfil', requiereJWT, (req, res) => {
    res.json({
      mensaje: `Hola ${req.jwt.nombre}`,
      rol: req.jwt.rol,
      expiraEnSegundos: Math.max(0, req.jwt.exp - Math.floor(Date.now() / 1000)),
    });
  });

  // Renovar: con un token todavía válido se pide uno nuevo (otro jti, otro vencimiento).
  app.post('/api/jwt/refresh', requiereJWT, (req, res) => {
    const { sub, usuario, nombre, rol } = req.jwt;
    res.json({ token: firmarToken({ id: sub, usuario, nombre, rol }) });
  });

  app.get('/api/jwt/reporte', requiereJWT, requiereRolJWT('admin'), (req, res) => {
    res.json({ reporte: 'Talleres: 3 · Alumnos inscritos: 120' });
  });

  // Logout con JWT: el token es de quien lo tenga; solo la lista negra permite "cancelarlo" antes de que venza.
  app.post('/api/jwt/logout', requiereJWT, async (req, res, next) => {
    try {
      if (config.jwtRevocar) {
        await tokens.revocar(req.jwt.jti, req.jwt.usuario, req.jwt.exp);
        return res.json({ mensaje: 'Token revocado: el servidor lo anotó en la lista negra.', revocado: true });
      }
      res.json({
        mensaje: 'El servidor no guarda nada: el token se borra del navegador, pero sigue sirviendo hasta que venza.',
        revocado: false,
      });
    } catch (error) {
      next(error);
    }
  });

  // Solo para la clase: la tabla tokens_revocados (un servidor real no la expone).
  app.get('/api/jwt/revocados', async (req, res, next) => {
    try {
      res.json({ jwtRevocar: config.jwtRevocar, revocados: await tokens.listar() });
    } catch (error) {
      next(error);
    }
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

  app.use(express.static(path.join(__dirname, 'public')));

  app.use((error, req, res, next) => {
    console.error(error);
    res.status(500).json({ error: '500 · Error del servidor' });
  });

  return app;
}

module.exports = { crearApp, NOMBRE_COOKIE };