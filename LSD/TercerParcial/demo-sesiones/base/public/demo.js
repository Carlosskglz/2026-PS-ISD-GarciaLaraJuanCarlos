// La página solo hace fetch a la API. El navegador manda la cookie solo (misma página, mismo servidor).
const $ = (id) => document.getElementById(id);

async function llamar(metodo, url, cuerpo) {
  const opciones = { method: metodo, headers: {} };
  if (cuerpo) {
    opciones.headers['Content-Type'] = 'application/json';
    opciones.body = JSON.stringify(cuerpo);
  }
  const respuesta = await fetch(url, opciones);
  let datos = null;
  try { datos = await respuesta.json(); } catch { datos = null; }
  return { status: respuesta.status, datos };
}

function anotar(metodo, url, status, datos) {
  const li = document.createElement('li');
  const clase = status < 300 ? 'ok' : status === 401 ? 'e401' : status === 403 ? 'e403' : 'error';
  li.innerHTML = `<span class="codigo ${clase}">${status}</span> <code>${metodo} ${url}</code>`;
  const cuerpo = document.createElement('pre');
  cuerpo.textContent = JSON.stringify(datos, null, 2);
  li.appendChild(cuerpo);
  $('bitacora').prepend(li);
}

async function refrescarEstado() {
  const { status, datos } = await llamar('GET', '/api/sesion');
  const estado = $('estado');
  if (status === 200) {
    estado.textContent = `${datos.usuario.nombre} · rol ${datos.usuario.rol} · sesión ${datos.sesion} · vence en ${datos.expiraEnSegundos} s`;
    estado.className = 'estado con-sesion';
  } else {
    estado.textContent = 'Sin sesión (el servidor responde 401)';
    estado.className = 'estado sin-sesion';
  }
  $('cookie-js').textContent = document.cookie || '(vacío)';
}

async function refrescarSesiones() {
  const { datos: respuesta } = await llamar('GET', '/api/diagnostico/sesiones');
  const datos = respuesta ? respuesta.sesiones : [];
  if (respuesta) {
    $('donde').textContent = respuesta.almacen === 'memoria'
      ? 'En la MEMORIA del servidor: se borra al reiniciarlo.'
      : 'En MySQL, tabla sessions. En Workbench: SELECT * FROM demo_sesiones.sessions;';
  }
  const cuerpo = $('tabla-sesiones');
  cuerpo.innerHTML = '';
  if (!datos || datos.length === 0) {
    cuerpo.innerHTML = '<tr><td colspan="4">(sin sesiones)</td></tr>';
    return;
  }
  for (const s of datos) {
    const fila = document.createElement('tr');
    if (s.esLaTuya) fila.className = 'tuya';
    const vence = s.expira ? new Date(s.expira).toLocaleTimeString() : '—';
    for (const valor of [s.sesion + (s.esLaTuya ? ' (la tuya)' : ''), s.usuario, s.visitas, vence]) {
      const celda = document.createElement('td');
      celda.textContent = valor;
      fila.appendChild(celda);
    }
    cuerpo.appendChild(fila);
  }
}

async function refrescarTodo() {
  await refrescarEstado();
  await refrescarSesiones();
}

$('usuario').addEventListener('change', () => {
  $('contrasena').value = `${$('usuario').value}12345`;
});

$('form-login').addEventListener('submit', async (evento) => {
  evento.preventDefault();
  const cuerpo = { usuario: $('usuario').value, contrasena: $('contrasena').value };
  const { status, datos } = await llamar('POST', '/api/login', cuerpo);
  anotar('POST', '/api/login', status, datos);
  await refrescarTodo();
});

for (const boton of document.querySelectorAll('[data-url]')) {
  boton.addEventListener('click', async () => {
    const { metodo, url } = boton.dataset;
    const { status, datos } = await llamar(metodo, url);
    anotar(metodo, url, status, datos);
    await refrescarTodo();
  });
}

$('btn-refrescar').addEventListener('click', refrescarTodo);
$('btn-sesiones').addEventListener('click', refrescarSesiones);

llamar('GET', '/api/config').then(({ datos }) => {
  $('config').textContent = JSON.stringify(datos, null, 2);
});
refrescarTodo();

// =====================================================================
// JWT (semana 13): el token NO viaja en una cookie; la página lo manda a mano en el encabezado Authorization.
// =====================================================================
let tokenJWT = '';

async function llamarJWT(metodo, url, cuerpo) {
  const opciones = { method: metodo, headers: {} };
  if (tokenJWT) opciones.headers.Authorization = `Bearer ${tokenJWT}`;
  if (cuerpo) {
    opciones.headers['Content-Type'] = 'application/json';
    opciones.body = JSON.stringify(cuerpo);
  }
  const respuesta = await fetch(url, opciones);
  let datos = null;
  try { datos = await respuesta.json(); } catch { datos = null; }
  return { status: respuesta.status, datos };
}

// Lee el payload (la parte de en medio del token). Es base64url, no está cifrado.
function leerPayload(token) {
  try {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

function pintarToken() {
  if (document.activeElement !== $('token')) $('token').value = tokenJWT; // no pisar lo que se está escribiendo
  const payload = tokenJWT ? leerPayload(tokenJWT) : null;
  $('token-payload').textContent = payload ? JSON.stringify(payload, null, 2) : '(sin token)';
  const vence = $('token-vence');
  if (!tokenJWT) {
    vence.textContent = 'Sin token';
  } else if (!payload || !payload.exp) {
    vence.textContent = 'Token con formato inválido';
  } else {
    const faltan = payload.exp - Math.floor(Date.now() / 1000);
    vence.textContent = faltan > 0 ? `El token vence en ${faltan} s` : 'El token ya venció';
  }
}

async function refrescarRevocados() {
  const { datos } = await llamar('GET', '/api/jwt/revocados');
  if (datos) {
    $('donde-jwt').textContent = datos.jwtRevocar
      ? 'jwtRevocar: true → el logout anota el token en la lista negra.'
      : 'jwtRevocar: false → el servidor no guarda nada, el token sirve hasta que venza.';
  }
  const cuerpo = $('tabla-revocados');
  cuerpo.innerHTML = '';
  const lista = datos ? datos.revocados : [];
  if (!lista || lista.length === 0) {
    cuerpo.innerHTML = '<tr><td colspan="4">(lista vacía)</td></tr>';
    return;
  }
  for (const r of lista) {
    const fila = document.createElement('tr');
    const valores = [`${String(r.jti).slice(0, 8)}...`, r.usuario, new Date(r.expira).toLocaleTimeString(), new Date(r.revocado_en).toLocaleTimeString()];
    for (const valor of valores) {
      const celda = document.createElement('td');
      celda.textContent = valor;
      fila.appendChild(celda);
    }
    cuerpo.appendChild(fila);
  }
}

function anotarJWT(metodo, url, status, datos) {
  const li = document.createElement('li');
  const clase = status < 300 ? 'ok' : status === 401 ? 'e401' : status === 403 ? 'e403' : 'error';
  li.innerHTML = `<span class="codigo ${clase}">${status}</span> <code>${metodo} ${url}</code>`;
  const cuerpo = document.createElement('pre');
  // Si la respuesta trae un token, se muestra acortado (el completo queda en la tarjeta 6).
  const copia = datos && datos.token ? { ...datos, token: `${datos.token.slice(0, 20)}...` } : datos;
  cuerpo.textContent = JSON.stringify(copia, null, 2);
  li.appendChild(cuerpo);
  $('bitacora-jwt').prepend(li);
}

// Si pegas o cambias el token a mano en el cuadro, se usa ese.
$('token').addEventListener('input', () => {
  tokenJWT = $('token').value.trim();
  pintarToken();
});

$('btn-jwt-login').addEventListener('click', async () => {
  const cuerpo = { usuario: $('usuario').value, contrasena: $('contrasena').value };
  const { status, datos } = await llamarJWT('POST', '/api/jwt/login', cuerpo);
  anotarJWT('POST', '/api/jwt/login', status, datos);
  if (status === 200) tokenJWT = datos.token;
  pintarToken();
});

for (const boton of document.querySelectorAll('[data-jwt-url]')) {
  boton.addEventListener('click', async () => {
    const { jwtMetodo: metodo, jwtUrl: url } = boton.dataset;
    const { status, datos } = await llamarJWT(metodo, url);
    anotarJWT(metodo, url, status, datos);
    if (url === '/api/jwt/refresh' && status === 200) tokenJWT = datos.token; // el token nuevo reemplaza al viejo
    pintarToken();
    await refrescarRevocados();
  });
}

$('btn-revocados').addEventListener('click', refrescarRevocados);

setInterval(pintarToken, 1000); // la cuenta regresiva del token
pintarToken();
refrescarRevocados();