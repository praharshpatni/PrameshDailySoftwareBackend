const express = require('express');
const router = express.Router();
const dbPool = require("./../DatabaseConnection/dbConfig.js")

const allowedTables = [
    { name: 'KYC', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'Transaction', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'FD', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'STP_Switch', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'Non_Financial', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'NSE_Pramesh', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'FFL_Transaction', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'FFL_STP_Switch', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'FFL_Non_Financial', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'NSE_FFL', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'RV_Transaction', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'RV_NSE', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'RV_Non_Financial', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' },
    { name: 'RV_STP_Switch', idCol: 'id', userCol: 'Created_By', dateCol: 'created_at' }
];

async function executeWithRetry(fn, maxRetries = 3) {
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        let conn;
        try {
            conn = await dbPool.getConnection();
            const result = await fn(conn);
            try { conn.release(); } catch (e) { /* best-effort */ }
            return result;
        } catch (err) {
            lastError = err;
            if (conn) {
                try { await conn.rollback().catch(() => { }); } catch (e) { }
                try { conn.release(); } catch (e) { }
            }
            // Retry only on deadlock (and optionally on lock wait timeout)
            if (attempt < maxRetries && (err && (err.code === 'ER_LOCK_DEADLOCK' || err.code === 'ER_LOCK_WAIT_TIMEOUT'))) {
                const backoff = Math.min(1000, 100 * attempt);
                console.warn(`DB transient error (${err.code}) attempt ${attempt}/${maxRetries}, retrying after ${backoff}ms`);
                await new Promise(r => setTimeout(r, backoff));
                continue;
            }
            break;
        }
    }
    throw lastError;
}

// Optional: test connection at module load — do not exit app here; just log.
dbPool.getConnection()
    .then((connection) => {
        console.log('✅ Connected to MySQL database (Pool ready)');
        connection.release(); // Release back to pool
    })
    .catch((err) => {
        console.error('❌ Database pool initialization failed:', err.stack);
        process.exit(1);
    });

router.get('/fetchAdminToshowNotification', async (req, res) => {
    try {
        const result = await executeWithRetry(async (conn) => {
            const [rows] = await conn.execute(
                'SELECT id, user_name, user_email, role FROM users WHERE role = ?',
                ['admin']
            );
            return rows;
        });

        res.json({ success: true, data: result });
    } catch (error) {
        console.error('Error in /fetchAdminToshowNotification:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch admin users' });
    }
});

router.get('/fetchNotifications', async (req, res) => {
    try {
        const allNotifications = await executeWithRetry(async (conn) => {
            let notifications = [];

            // Loop over each table and query today's entries
            for (const table of allowedTables) {
                const query = `
                    SELECT 
                        ${table.idCol} AS rowId,
                        ${table.userCol} AS rmName,
                        ${table.dateCol} AS date
                    FROM ${table.name}
                    WHERE DATE(${table.dateCol}) = CURDATE()
                    ORDER BY ${table.dateCol} DESC
                `;

                const [rows] = await conn.execute(query);

                // Map rows to notification format
                rows.forEach((row) => {
                    notifications.push({
                        tableName: table.name,
                        rowId: row.rowId,
                        rmName: row.rmName,
                        date: new Date(row.date).toISOString()
                    });
                });
            }

            // Assign unique incremental IDs across all entries
            return notifications
                .sort((a, b) => new Date(b.date) - new Date(a.date)) // Global DESC sort by date (newest first)
                .map((notif, index) => ({
                    ...notif,
                    id: index + 1
                }));
        });


        res.json({ success: true, data: allNotifications });
    } catch (error) {
        console.error('❌ Database error in fetchNotifications:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch notifications' });
    }
});

module.exports = router;