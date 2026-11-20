// La lista negra: consultas a la tabla tokens_revocados. Siempre con ? (consulta parametrizada).

function crearModeloTokens(pool) {
  // Anota un token como revocado (logout). exp viene en SEGUNDOS desde 1970, como en el JWT.
  async function revocar(jti, usuario, exp) {
    await pool.query(
      'INSERT IGNORE INTO tokens_revocados (jti, usuario, expira) VALUES (?, ?, FROM_UNIXTIME(?))',
      [jti, usuario, exp]
    );
  }

  // ¿Este token está en la lista negra?
  async function estaRevocado(jti) {
    const [filas] = await pool.query('SELECT 1 FROM tokens_revocados WHERE jti = ?', [String(jti || '')]);
    return filas.length > 0;
  }

  // Toda la lista (para la tarjeta 8 de la página).
  async function listar() {
    const [filas] = await pool.query(
      'SELECT jti, usuario, expira, revocado_en FROM tokens_revocados ORDER BY revocado_en DESC, jti'
    );
    return filas;
  }

  return { revocar, estaRevocado, listar };
}

module.exports = { crearModeloTokens };