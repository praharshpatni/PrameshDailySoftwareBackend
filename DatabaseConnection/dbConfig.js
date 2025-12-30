const mysql = require('mysql2/promise');

// === ✅ MySQL Database Connection ===

const poolConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    acquireTimeout: 60000,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    reconnect: true,
    idleTimeout: 600000,
};
dbPool = mysql.createPool(poolConfig);


module.exports = dbPool;