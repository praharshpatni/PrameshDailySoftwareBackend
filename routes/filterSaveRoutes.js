// routes/filters.js
const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');

// === MySQL Pool (Production ready) ===
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

console.log('✅ MySQL connection pool initialized');

// === Input Validation ===
function validateInputs(userEmail, tableName) {
    if (typeof userEmail !== 'string' || typeof tableName !== 'string') {
        const err = new Error('Invalid input types');
        err.status = 400;
        throw err;
    }
    if (!userEmail.trim() || !tableName.trim()) {
        const err = new Error('Missing userEmail or tableName');
        err.status = 400;
        throw err;
    }
    if (userEmail.length > 255 || tableName.length > 64) {
        const err = new Error('Input too long');
        err.status = 400;
        throw err;
    }
}

// === Deadlock-safe executor ===
async function executeWithRetry(fn, maxRetries = 3) {
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        let conn;
        try {
            conn = await pool.getConnection();
            const result = await fn(conn);
            conn.release();
            return result;
        } catch (err) {
            lastError = err;
            if (conn) {
                try { await conn.rollback().catch(() => { }); } catch { }
                conn.release();
            }
            if (attempt < maxRetries && err.code === 'ER_LOCK_DEADLOCK') {
                console.warn(`Deadlock attempt ${attempt}/${maxRetries}, retrying...`);
                await new Promise(r => setTimeout(r, 100 * attempt));
                continue;
            }
            break;
        }
    }
    throw lastError;
}

// === GET /api/getFilters ===
router.get('/getFilters', async (req, res) => {
    try {
        const { userEmail, tableName } = req.query;
        validateInputs(userEmail, tableName);

        const result = await executeWithRetry(async (conn) => {
            const [rows] = await conn.execute(
                'SELECT column_name, filter_applied, filtered_row_count FROM user_filters WHERE user_email = ? AND table_name = ?',
                [userEmail, tableName]
            );

            const filters = {};
            let filteredRowCount = null;

            for (const row of rows) {
                if (row.filter_applied) {
                    try {
                        filters[row.column_name] = JSON.parse(row.filter_applied);
                    } catch {
                        filters[row.column_name] = row.filter_applied;
                    }
                }
                if (filteredRowCount === null && row.filtered_row_count !== null) {
                    filteredRowCount = Number(row.filtered_row_count);
                }
            }

            return { filters, filteredRowCount };
        });

        res.json(result);
    } catch (error) {
        console.error('GET /getFilters error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to fetch filters' });
    }
});

// === POST /api/saveFilters ===
router.post('/saveFilters', async (req, res) => {
    try {
        const { userEmail, tableName, filters, filteredRowCount } = req.body;
        validateInputs(userEmail, tableName);

        if (!filters || typeof filters !== 'object' || Array.isArray(filters)) {
            const err = new Error('Invalid filters object');
            err.status = 400;
            throw err;
        }

        await executeWithRetry(async (conn) => {
            await conn.beginTransaction();

            try {
                // DON'T delete all filters first - this causes the race condition
                // Instead, update existing ones and insert new ones

                // console.log("before object ", filters)
                const filterEntries = Object.entries(filters);
                // console.log("after object ", filterEntries)

                if (filterEntries.length === 0) {
                    // If no filters, delete all for this user/table
                    await conn.execute(
                        'DELETE FROM user_filters WHERE user_email = ? AND table_name = ?',
                        [userEmail, tableName]
                    );
                } else {
                    // Get current filter columns for this user/table
                    const [currentFilters] = await conn.execute(
                        'SELECT column_name FROM user_filters WHERE user_email = ? AND table_name = ?',
                        [userEmail, tableName]
                    );

                    console.log("current Filters", currentFilters)
                    const currentColumns = new Set(currentFilters.map(row => row.column_name));
                    console.log("current Colums", currentColumns)
                    const newColumns = new Set(Object.keys(filters));
                    console.log("New Colums", newColumns);

                    // Delete columns that are no longer in the new filters
                    const columnsToDelete = [...currentColumns].filter(col => !newColumns.has(col));
                    for (const column of columnsToDelete) {
                        await conn.execute(
                            'DELETE FROM user_filters WHERE user_email = ? AND table_name = ? AND column_name = ?',
                            [userEmail, tableName, column]
                        );
                    }

                    // Update or insert remaining columns
                    for (const [columnName, values] of filterEntries) {
                        if (!Array.isArray(values) || values.length === 0) {
                            // Delete if empty array
                            await conn.execute(
                                'DELETE FROM user_filters WHERE user_email = ? AND table_name = ? AND column_name = ?',
                                [userEmail, tableName, columnName]
                            );
                        } else {
                            await conn.execute(
                                `INSERT INTO user_filters 
                                 (user_email, table_name, column_name, filter_applied, filtered_row_count, updated_at)
                                 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                                 ON DUPLICATE KEY UPDATE 
                                   filter_applied = VALUES(filter_applied),
                                   filtered_row_count = VALUES(filtered_row_count),
                                   updated_at = CURRENT_TIMESTAMP`,
                                [userEmail, tableName, columnName, JSON.stringify(values), filteredRowCount ?? null]
                            );
                        }
                    }
                }

                await conn.commit();
            } catch (txErr) {
                await conn.rollback().catch(() => { });
                throw txErr;
            }
        });

        res.json({ success: true });
    } catch (error) {
        console.error('POST /saveFilters error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to save filters' });
    }
});

module.exports = router;