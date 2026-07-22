const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.on('error', (err) => {
  // 28P01 = invalid_password — expected during startup before DB is ready
  if (err.code !== '28P01') console.error('DB pool error:', err.message);
});

module.exports = pool;
