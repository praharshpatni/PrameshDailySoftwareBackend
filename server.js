const dotenv = require('dotenv');
const path = require('path');
// const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
dotenv.config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const useragent = require('express-useragent');
const os = require('os');
const nodemailer = require('nodemailer');
// const https = require('https');
const http = require('http');
const compression = require('compression');
const socketIO = require('socket.io');
const mysql = require('mysql2/promise');
const cors = require("cors");
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

const allowedOrigins = [
    'http://localhost:3000',
    'http://192.168.0.135:3000',
    'http://192.168.0.135:4000',
    "http://192.168.0.136:4000",
    "http://192.168.0.136:3000",
    "http://192.168.0.194:3000",
    "http://192.168.0.194:4000",
    "http://192.168.0.192:4000",
    "http://192.168.0.192:3000"
];
const io = socketIO(server, {
    cors: {
        origin: ["http://192.168.1.4:4000", "http://192.168.0.192:3000", "http://192.168.0.192:4000",
            "http://192.168.0.194:3000", "http://192.168.0.194:4000", "http://192.168.0.135:3000", "http://192.168.0.135:4000", "http://192.168.1.4:3000", , 'http://localhost:4000', 'http://localhost:3000', "http://192.168.29.34:3000", "http://192.168.29.34:4000", "http://192.168.0.179:3000", "http://192.168.0.179:4000"],
        methods: ['GET', 'POST'],
    }
});
const { router: chatRoutes, initializeChat } = require('./routes/chatRoutes')
const headerRoputes = require('./routes/headerRoutes')
const dropdownRoutes = require("./routes/dropdownRoutes");
const filterSaveRoutes = require("./routes/filterSaveRoutes");
const { error } = require('console');


app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

let db = require("./DatabaseConnection/dbConfig")

db.getConnection()
    .then((connection) => {
        console.log('✅ Connected to MySQL database (Pool ready)');
        connection.release(); // Release back to pool
    })
    .catch((err) => {
        console.error('❌ Database pool initialization failed:', err.stack);
        process.exit(1); // Exit if DB is down (critical for startup)
    });


initializeChat(io, db);

const smtpHost = process.env.SMTP_HOST || 'mail.prameshwealth.com';
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpSecure = (process.env.SMTP_SECURE === 'true'); // true => port 465, false => 587 STARTTLS
const tlsReject = (process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false');

const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        minVersion: 'TLSv1.2',
        // Set rejectUnauthorized=false only if your host uses self-signed cert and you accept the risk
        rejectUnauthorized: tlsReject
    },
    greetingTimeout: 10000,
});

(async function verifyMailer() {
    try {
        await transporter.verify();
        console.log('✅ SMTP transporter verified (ready to send).');
    } catch (err) {
        console.error('❌ SMTP transporter verification failed:', err && err.message ? err.message : err);
        // don't exit the process — log and allow server to run; you can optionally exit in prod
    }
})();

function fromAddress() {
    const email = process.env.EMAIL || 'no-reply@prameshwealth.com';
    return `"Pramesh Team" <${email}>`;
}
async function sendLoginAttemptEmail(toEmail, deviceName) {
    if (!toEmail) {
        console.warn('sendLoginAttemptEmail: missing toEmail');
        return;
    }
    const mailOptions = {
        from: fromAddress(),
        to: toEmail,
        subject: '🔒 Security Alert: Unauthorized Login Attempt Detected',
        text: `Hello,\n\nWe detected a login attempt to your Pramesh account from device: ${deviceName}.\n\nIf this wasn't you, change your password immediately and contact support.\n\n– Pramesh Security Team`,
        html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
        <h2 style="color: #E63946;">🔒 Unauthorized Login Attempt</h2>
        <p>Dear user,</p>
        <p>We detected an attempt to access your <strong>Pramesh Data Entry System</strong> account from the following device:</p>
        <p style="font-size: 16px; color: #0D1B2A;"><strong>Device Name:</strong> ${deviceName}</p>
        <p>If this attempt was <strong>not</strong> made by you, please change your password and contact <a href="mailto:support@pramesh.com">support@pramesh.com</a></p>
        <p style="margin-top: 30px;">– Pramesh Security Team</p>
      </div>
    `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Security alert email sent to', toEmail, info.response || info);
        return { ok: true, info };
    } catch (error) {
        console.error('❌ Failed to send security alert email to', toEmail, error);
        return { ok: false, error };
    }
}

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));


// === 🌐 Express Middleware ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// app.use(express.json({ limit: '100mb' }));
app.use(compression({
    threshold: 0,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));


app.use(useragent.express());
// === 📋 Route Logger Middleware ===
app.use((req, res, next) => {
    let color;

    switch (req.method) {
        case 'GET':
            color = '\x1b[32m'; // Green
            break;
        case 'POST':
        case 'PUT':
            color = '\x1b[33m'; // Yellow
            break;
        case 'DELETE':
            color = '\x1b[31m'; // Red
            break;
        default:
            color = '\x1b[0m';  // Reset (default)
    }

    console.log(`${color}${req.method} ${req.url}\x1b[0m`); // Reset color at end
    next();
});

// middlewares for route 
app.use('/chat', chatRoutes);
app.use('/header', headerRoputes);
app.use('/api', dropdownRoutes);
app.use('/filter', filterSaveRoutes);

const queryLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10, // limit to 10 queries per minute per IP
    message: 'Too many queries, slow down.',
});

app.use('/api/run-query', queryLimiter);

const allowedTables = ['KYC', 'Transaction', 'STP_Switch', 'Non_Financial', 'NSE_Pramesh', 'FFL_Transaction', 'FFL_STP_Switch', 'FFL_Non_Financial', 'NSE_FFL', 'RV_Transaction', 'RV_NSE', 'RV_Non_Financial', 'RV_STP_Switch', 'FD'];
const emailToRMMap = {
    'vishal@prameshwealth.com': 'Vishal Vaidya',
    "bhumika@prameshwealth.com": "Bhumika",
    "happy@prameshwealth.com": "Happy",
    "vinayak@prameshwealth.com": "Vinayak Shelar",
    "navneet@prameshwealth.com": "Navneet Mishra"
};

const unrestricted_adminEmails = ['admin@gmail.com', 'praharsh@prameshwealth.com', 'prachi@prameshwealth.com', 'arpita@prameshwealth.com', "krishna@prameshwealth.com", "shweta@prameshwealth.com"];

// WHATS APP ROUTES 
// GET /chat/unread-counts?currentUserEmail=xyz@example.com
// app.get('/chat/unread-counts', async (req, res) => {
//     const { currentUserEmail } = req.query;
//     if (!currentUserEmail) return res.status(400).json({ error: "Missing email" });

//     try {
//         const [rows] = await db.execute(`
//             SELECT sender_email, COUNT(*) as unread_count
//             FROM messages
//             WHERE receiver_email = ?
//               AND read_at IS NULL
//             GROUP BY sender_email
//         `, [currentUserEmail]);

//         const counts = {};
//         rows.forEach(row => {
//             counts[row.sender_email] = row.unread_count;
//         });

//         res.json({ unreadCounts: counts });
//     } catch (err) {
//         console.error("Error fetching unread counts:", err);
//         res.status(500).json({ error: "Server error" });
//     }
// });
// GET /chat/unread-counts?currentUserEmail=xyz@example.com
app.get('/chat/unread-counts', async (req, res) => {
    const { currentUserEmail } = req.query;

    if (!currentUserEmail) {
        return res.status(400).json({ error: "Missing currentUserEmail" });
    }

    try {
        const [rows] = await db.execute(`
            SELECT 
                other_user_email,
                COUNT(CASE WHEN receiver_email = ? AND read_at IS NULL THEN 1 END) AS unread_count,
                MAX(sent_at) AS last_message_time
            FROM (
                SELECT 
                    CASE 
                        WHEN sender_email = ? THEN receiver_email
                        ELSE sender_email
                    END AS other_user_email,
                    sent_at,
                    receiver_email,
                    read_at
                FROM messages
                WHERE sender_email = ? OR receiver_email = ?
            ) AS subquery
            GROUP BY other_user_email
        `, [
            currentUserEmail,  // for COUNT unread
            currentUserEmail,  // for CASE in subquery
            currentUserEmail,  // WHERE sender
            currentUserEmail   // WHERE receiver
        ]);

        const unreadCounts = {};
        const lastMessageTimes = {};
        console.log("unread count", unreadCounts)
        console.log("lastmessage time", lastMessageTimes)

        rows.forEach(row => {
            const email = row.other_user_email;
            unreadCounts[email] = parseInt(row.unread_count) || 0;
            lastMessageTimes[email] = row.last_message_time;
        });

        res.json({
            unreadCounts,
            lastMessageTimes
        });

    } catch (err) {
        console.error("Error fetching unread counts & last times:", err);
        res.status(500).json({ error: "Server error" });
    }
});
// POST /chat/mark-as-read
app.post('/chat/mark-as-read', async (req, res) => {
    const { currentUserEmail, otherUserEmail } = req.body;
    console.log("current user email", currentUserEmail)

    if (!currentUserEmail || !otherUserEmail) {
        return res.status(400).json({ error: "Missing emails" });
    }

    try {
        await db.execute(`
            UPDATE messages
            SET read_at = NOW()
            WHERE receiver_email = ?
              AND sender_email = ?
              AND read_at IS NULL
        `, [currentUserEmail, otherUserEmail]);

        res.json({ success: true });
    } catch (err) {
        console.error("Error marking as read:", err);
        res.status(500).json({ error: "Server error" });
    }
});


// starting of whats app configuration route 
app.get('/chat/fetchActiveUsers', async (req, res) => {
    const { currentUserEmail } = req.query;
    if (!currentUserEmail) return res.status(400).json({ error: 'Email required' });

    try {
        const [rows] = await db.execute(
            `SELECT user_email AS email, user_name, is_logged_in 
             FROM users 
             WHERE user_email != ? 
             ORDER BY is_logged_in DESC, user_name ASC`,
            [currentUserEmail]
        );
        res.json({ users: rows });
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/chat/messages', async (req, res) => {
    const { currentUserEmail, otherUserEmail } = req.query;
    if (!currentUserEmail || !otherUserEmail) return res.status(400).json({ error: 'Emails required' });

    try {
        const [rows] = await db.execute(
            `SELECT m.*, r.message_text AS reply_text, r.sender_email AS reply_sender_email
             FROM messages m
             LEFT JOIN messages r ON m.reply_to_id = r.id
             WHERE (m.sender_email = ? AND m.receiver_email = ?)
                OR (m.sender_email = ? AND m.receiver_email = ?)
             ORDER BY m.sent_at ASC`,
            [currentUserEmail, otherUserEmail, otherUserEmail, currentUserEmail]
        );
        res.json({ messages: rows });
    } catch (err) {
        console.error('Error fetching messages:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ending of whats app configuration route 


app.post('/user/update-autosave', async (req, res) => {
    const { email, is_autosave_on } = req.body;
    try {
        const [result] = await db.query(
            'UPDATE users SET is_autosave_on = ? WHERE user_email = ?',
            [is_autosave_on, email]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ success: true });
    } catch (err) {
        console.error('Update autosave error:', err);
        res.status(500).json({ error: 'Failed to update autosave status' });
    }
});

app.get('/user/autosave-status/:email', async (req, res) => {
    const { email } = req.params;
    try {
        const [rows] = await db.query(
            'SELECT is_autosave_on FROM users WHERE user_email = ?',
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const is_autosave_on = rows[0].is_autosave_on || false;
        res.json({ is_autosave_on });
    } catch (err) {
        console.error('Error fetching autosave status:', err);
        res.status(500).json({ error: 'Failed to fetch autosave status' });
    }
});


app.post('/api/logDownload', async (req, res) => {
    const { user_email, table_name, file_type } = req.body;
    const ip_address = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const user_agent = req.headers['user-agent'];

    if (!user_email || !table_name || !file_type) {
        return res.status(400).json({ error: "Missing fields" });
    }

    try {
        await db.query(
            'INSERT INTO download_logs (user_email, table_name, file_type, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
            [user_email, table_name, file_type, ip_address, user_agent]
        );
        res.json({ message: "Download logged successfully" });
    } catch (err) {
        console.error("❌ Failed to log download:", err);
        res.status(500).json({ error: "Logging failed" });
    }
});


// for importing excel file 
app.use(express.json()); // ✅ Needed to parse JSON body

const excelDateToMySQLDate = (value) => {
    if (typeof value === 'number') {
        const excelEpoch = new Date(Date.UTC(1899, 11, 30));
        const mysqlDate = new Date(excelEpoch.getTime() + value * 86400 * 1000);
        return mysqlDate.toISOString().split('T')[0]; // 'YYYY-MM-DD'
    }

    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return value;

    const match = value.match(/^(\d{2})[-\/](\d{2})[-\/](\d{4})$/);
    if (match) {
        const [, dd, mm, yyyy] = match;
        const parsedDate = new Date(`${yyyy}-${mm}-${dd}`);
        if (isNaN(parsedDate)) {
            console.warn(`⚠️ Invalid date after parsing: ${value}`);
            return null;
        }
        return parsedDate.toISOString().split('T')[0];
    }

    return null;
};

const cleanAmount = (val) => {
    if (typeof val === 'string') {
        const cleaned = parseFloat(val.replace(/,/g, ''));
        return isNaN(cleaned) ? null : cleaned;
    }
    if (typeof val === 'number') return val;
    return null;
};

app.post('/api/importExcel', async (req, res) => {
    const { tableName, rows, created_by, importMode = 'override' } = req.body;

    if (!tableName || !rows || !Array.isArray(rows)) {
        return res.status(400).json({ message: "Invalid request body" });
    }
    if (!allowedTables.includes(tableName)) {
        return res.status(400).json({ message: "Invalid table name" });
    }

    // Date conversion helper - more robust
    const excelDateToMySQLDate = (value) => {
        if (value === null || value === undefined || value === '' || value === 'Showing') return null;
        const str = value.toString().trim();
        if (!str) return null;
        let date;
        // Try standard Date parsing first (handles YYYY-MM-DD well)
        date = new Date(str);
        if (isNaN(date.getTime())) {
            // Try parsing with separators (prioritize DD/MM/YYYY, DD-MM-YYYY)
            const parts = str.split(/[\/\-\\.]/);
            if (parts.length === 3) {
                let day = parseInt(parts[0], 10);
                let month = parseInt(parts[1], 10);
                let year = parseInt(parts[2], 10);
                // Handle 2-digit year
                if (year < 100) {
                    year = year > 50 ? 1900 + year : 2000 + year;
                }
                // Try DD-MM-YYYY first
                if (month >= 1 && month <= 12 && day >= 1 && day <= 31 && year >= 1900 && year <= 2100) {
                    date = new Date(year, month - 1, day);
                    // Validate no overflow
                    if (isNaN(date.getTime()) || date.getDate() !== day) {
                        // Fallback: MM-DD-YYYY
                        [day, month] = [month, day];
                        date = new Date(year, month - 1, day);
                    }
                }
            }
        }
        if (isNaN(date.getTime())) {
            console.warn(`📅 Could not parse date: "${str}"`);
            return null;
        }
        const y = date.getFullYear();
        if (!y || y < 1900 || y > 2100) return null;
        const formatted = `${y}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;

        return formatted;
    };

    // Numeric cleaning helper - preserve all valid numbers including 0
    const cleanNumeric = (value, isInteger) => {
        if (value === null || value === undefined || value === '') return null;
        if (value === 0 || value === '0') return 0;
        if (typeof value === 'number') {
            if (isNaN(value)) return null;
            return isInteger ? Math.floor(value) : value;
        }
        const strVal = value.toString().trim();
        if (!strVal) return null;

        // Remove commas and other non-numeric chars except . and -
        const cleaned = strVal.replace(/,/g, '').replace(/[^\d.-]/g, '');
        if (!cleaned || cleaned === '-' || cleaned === '.') return null;

        const num = isInteger ? parseInt(cleaned, 10) : parseFloat(cleaned);
        return isNaN(num) ? null : num;
    };

    // Clean string value - preserve empty strings as null, trim whitespace
    const cleanString = (value) => {
        if (value === null || value === undefined) return null;
        const str = value.toString().trim();
        return str === '' ? null : str;
    };

    try {
        // Get table schema
        const [columnsResult] = await db.execute(`SHOW COLUMNS FROM \`${tableName}\``);
        const validColumns = columnsResult.map(col => col.Field);
        const columnTypes = {};
        const columnNullable = {};
        const columnDefaults = {};

        columnsResult.forEach(col => {
            columnTypes[col.Field] = col.Type.toLowerCase();
            columnNullable[col.Field] = col.Null === 'YES';
            columnDefaults[col.Field] = col.Default;
        });

        // Map incoming rows to DB format
        const mappedRows = rows.map((row, rowIndex) => {
            const data = { ...row };
            if (created_by) data.created_by = created_by;

            const mapped = {};

            for (const key in data) {
                // Normalize key: lowercase, replace non-alnum with _, trim
                let normKey = key.trim().toLowerCase().replace(/[^a-z0-9]/g, '_');
                // Remove leading/trailing underscores
                normKey = normKey.replace(/^_+|_+$/g, '');
                // Handle common typos (keep as exact match)
                if (normKey === 'cheqe_no') normKey = 'cheque_no'; // Lowercase for consistency, but adjust to DB case later
                // Find matching column (case-insensitive)
                const matchedCol = validColumns.find(col => col.toLowerCase() === normKey);
                if (matchedCol) {
                    let value = data[key];
                    const colType = columnTypes[matchedCol];
                    // Skip auto-increment ID columns
                    if (matchedCol.toLowerCase() === 'id' && colType.includes('int') && value === '') {
                        continue;
                    }

                    // FIXED: More precise date column detection
                    // Only treat as date if column name exactly matches common date patterns
                    // or column type explicitly contains 'date'
                    const isDateColumn =
                        colType.includes('date') ||
                        colType.includes('timestamp') ||
                        matchedCol.toLowerCase() === 'date' ||
                        matchedCol.toLowerCase() === 'transaction_date' ||
                        matchedCol.toLowerCase() === 'created_date' ||
                        matchedCol.toLowerCase() === 'updated_date' ||
                        matchedCol.toLowerCase() === 'entry_date' ||
                        matchedCol.toLowerCase() === 'value_date' ||
                        matchedCol.toLowerCase().endsWith('_date') ||
                        matchedCol.toLowerCase().startsWith('date_');

                    // Process based on column type
                    if (isDateColumn) {
                        value = excelDateToMySQLDate(value);
                    } else if (colType.includes('int') || colType.includes('decimal') || colType.includes('float') || colType.includes('double') || colType.includes('numeric')) {
                        value = cleanNumeric(value, colType.includes('int'));
                    } else if (colType.includes('char') || colType.includes('text') || colType.includes('varchar')) {
                        value = cleanString(value);
                    } else {
                        value = cleanString(value);
                    }
                    mapped[matchedCol] = value; // Use exact DB column name
                } else {
                    // Log unmatched for debugging (first 5 per row)
                    if (Object.keys(mapped).length < 5) {
                        console.warn(`🔍 Unmatched header "${key}" (norm: "${normKey}") for table ${tableName}`);
                    }
                }
            }

            return mapped;
        });

        // Log sample mapped row for debugging
        if (mappedRows.length > 0) {
            console.log(`🔍 Sample mapped row (first):`, JSON.stringify(mappedRows[0], null, 2));
            console.log(`🔍 Columns being inserted:`, Object.keys(mappedRows[0]).join(', '));
        }

        // Fetch existing data count
        const [countResult] = await db.execute(`SELECT COUNT(*) as total FROM \`${tableName}\``);
        const totalExisting = countResult[0].total;

        let successCount = 0;
        let skipped = [];
        let mode = importMode;
        const errorSummary = {};

        if (importMode === 'override' && totalExisting > 0) {
            console.log(`🔄 Override mode: Clearing ${totalExisting} existing rows from ${tableName}`);
            await db.execute(`DELETE FROM \`${tableName}\``);

            // Reset auto-increment if needed
            try {
                await db.execute(`ALTER TABLE \`${tableName}\` AUTO_INCREMENT = 1`);
            } catch (e) {
                // Ignore if table doesn't have auto-increment
            }
        }

        // Insert rows one by one with detailed error tracking
        for (const [index, mapped] of mappedRows.entries()) {
            try {
                const colNames = Object.keys(mapped);
                const colValues = Object.values(mapped);

                // Skip empty rows
                if (colNames.length === 0) {
                    skipped.push({ index: index + 1, reason: 'Empty row - no valid columns' });
                    continue;
                }

                const columns = colNames.map(c => `\`${c}\``).join(', ');
                const placeholders = colValues.map(() => '?').join(', ');

                const query = `INSERT INTO \`${tableName}\` (${columns}) VALUES (${placeholders})`;

                await db.execute(query, colValues);
                successCount++;

            } catch (rowError) {
                const errMsg = rowError.message || 'Unknown error';
                const errType = errMsg.includes(':') ? errMsg.split(':')[0].trim().toLowerCase() : 'error';
                errorSummary[errType] = (errorSummary[errType] || 0) + 1;

                // Log detailed error for first few failures
                if (skipped.length < 5) {
                    console.error(`❌ Row ${index + 1} failed:`, errMsg);
                    console.error(`   Data:`, JSON.stringify(mapped, null, 2));
                }

                skipped.push({
                    index: index + 1,
                    reason: errMsg,
                    data: mapped // Include data for debugging
                });
            }
        }

        console.log(`✅ Import complete (${mode}): ${successCount} success, ${skipped.length} skipped`);

        if (Object.keys(errorSummary).length > 0) {
            console.log(`📊 Error summary:`, errorSummary);
        }

        res.status(200).json({
            message: mode === 'override'
                ? `🔄 Override: ${successCount} rows replaced existing ${totalExisting} rows.`
                : `➕ Append: ${successCount} rows added to existing ${totalExisting} rows.`,
            mode,
            previousRowCount: totalExisting,
            skipped: skipped.slice(0, 100), // Limit skipped array size in response
            totalSkipped: skipped.length,
            totalProcessed: rows.length,
            successCount,
            errorSummary
        });

    } catch (error) {
        console.error("❌ MySQL Error:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

const validateUserFromSession = (req, res, next) => {
    const email = req.headers['x-user-email'];
    const name = req.headers['x-user-name'];

    if (!email || !name) {
        return res.status(401).json({ error: 'User not identified. Please log in again.' });
    }

    req.user = { email, name };
    next();
};

app.post('/api/search', validateUserFromSession, async (req, res) => {
    const { table, query } = req.body;

    if (!allowedTables.includes(table)) {
        console.log('Invalid table name:', table);
        return res.status(400).json({ error: 'Invalid table name' });
    }

    if (!query) {
        console.log('No query provided');
        return res.status(400).json({ error: 'Query parameter is required' });
    }

    try {
        // Get column names for the table
        const [columns] = await db.query(`SHOW COLUMNS FROM \`${table}\` WHERE Type LIKE '%char%' OR Type LIKE '%text%'`);
        const textColumns = columns.map(col => col.Field);

        if (textColumns.length === 0) {
            console.log('No text columns found for table:', table);
            return res.status(400).json({ error: 'No searchable text columns found' });
        }

        // Build dynamic SQL query to search across all text columns
        const conditions = textColumns.map(col => `\`${col}\` LIKE ?`).join(' OR ');
        const params = Array(textColumns.length).fill(`%${query}%`);
        const sql = `SELECT * FROM \`${table}\` WHERE ${conditions} AND is_deleted = 0`;

        console.log('Executing query:', sql, 'Params:', params);
        const [rows] = await db.query(sql, params);

        res.json(rows);
    } catch (error) {
        console.error('Search error:', error.message, error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/run-query', validateUserFromSession, async (req, res) => {
    let { query } = req.body;

    if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Query is required' });
    }

    const originalQuery = query;
    // const lowerQuery = query.trim().toLowerCase();

    //  Only allow SELECT queries
    if (!/^\s*select\b/i.test(query)) {
        return res.status(403).json({ error: 'Only SELECT queries are allowed.' });
    }

    //  Prevent SQL injection via semicolon, comments, DDL/DML
    if (/--|\/\*|\*\/|;/i.test(query)) {
        return res.status(403).json({ error: 'SQL comments or multiple statements are not allowed.' });
    }

    if (/(drop|insert|delete|update|alter|create)\b/i.test(query)) {
        return res.status(403).json({ error: 'Unsafe SQL operations are blocked.' });
    }

    // ✅ Extract table and validate access
    const match = query.match(/from\s+([^\s;]+)/i);
    const tableName = match ? match[1].replace(/[`"]/g, '') : null;

    if (!tableName || !allowedTables.map(t => t.toLowerCase()).includes(tableName.toLowerCase())) {
        return res.status(403).json({ error: `Access to table "${tableName}" is not allowed.` });
    }

    // ✅ Automatically add is_deleted = 0 filter
    if (/select\s+\*\s+from\s+/i.test(query)) {
        const isAlreadyFiltered = /\bis_deleted\s*=\s*\d\b/i.test(query);
        const match = query.match(/select \* from\s+([^\s;]+)/i);

        if (match && !isAlreadyFiltered) {
            const tableName = match[1];
            const rest = query.replace(/select \* from\s+[^\s;]+/i, '');

            if (/where\s+/i.test(rest)) {
                query = `SELECT * FROM ${tableName} ${rest.replace(/where/i, 'WHERE')} AND is_deleted = 0`;
            } else {
                query = `SELECT * FROM ${tableName} WHERE is_deleted = 0${rest}`;
            }
        }
    }

    // ✅ Apply a limit if not already present
    if (!/limit\s+\d+/i.test(query)) {
        query += ' LIMIT 100';
    }

    try {
        // ✅ Log the executed query with user info
        await db.query(
            'INSERT INTO query_logs (query_text, user_email, endpoint) VALUES (?, ?, ?)',
            [originalQuery, req.user.email, '/api/run-query']
        );

        // ✅ Run the query securely with a timeout
        const [rows] = await db.query({ sql: query, timeout: 5000 });

        res.json({ rows });
    } catch (err) {
        console.error('Query execution error:', err);
        res.status(500).json({ error: 'Invalid query or internal server error' });
    }
});


// user login and logout route 

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const sqlInjectionPattern = /('|--|;|\/\*|\*\/)/i;
    if (
        typeof email !== 'string' ||
        typeof password !== 'string' ||
        sqlInjectionPattern.test(email) ||
        sqlInjectionPattern.test(password)
    ) {
        return res.status(400).json({ error: 'Invalid input format.' });
    }
    try {
        // 1. Fetch user
        const [users] = await db.query('SELECT * FROM users WHERE user_email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }
        const user = users[0];
        // 2. Validate password
        const isPasswordValid = (password === user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // 3. Check admin approval status (only for RM role; skip for admin)
        if (user.role === 'rm' && user.is_approved_by_admin === 'pending') {
            return res.status(402).json({ message: 'pending', error: 'Access not allowed by admin. Your request is pending approval.' });
        }
        if (user.role === 'rm' && user.is_approved_by_admin === 'rejected') {
            return res.status(402).json({ message: 'rejected', error: 'Access not allowed by admin. Your request is pending approval.' });
        }
        // 4. Check is_logged_in and send email if already logged in
        if (user.is_logged_in) {
            console.log("Email Sending...")
            const deviceName = os.hostname();
            sendLoginAttemptEmail(user.user_email, deviceName); // 👈 send unauthorized login alert
            return res.status(403).json({ error: 'User is already logged in on another device' });
        }
        // 5. Mark as logged in
        await db.query('UPDATE users SET is_logged_in = 1, login_time = NOW(), logout_time = NULL, session_duration = NULL WHERE user_email = ?', [email]);
        io.emit("logintoPrameshDataSystem")
        // 6. Return success
        res.json({
            email: user.user_email,
            name: user.user_name
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        // Server-side validation (unchanged)
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Please fill all fields' });
        }

        const trimmedUsername = username.trim();
        const trimmedEmail = email.trim();
        const trimmedPassword = password.trim();

        if (trimmedUsername.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(trimmedEmail)) {
            return res.status(400).json({ error: 'Please enter a valid email address' });
        }

        if (trimmedPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const [existingUsers] = await db.execute(
            'SELECT id FROM users WHERE user_name = ? OR user_email = ?',
            [trimmedUsername, trimmedEmail]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }


        // Insert new user with role='rm', is_approved_by_admin='pending'
        const [insertResult] = await db.execute(
            'INSERT INTO users (user_name, user_email, password, role, is_approved_by_admin) VALUES (?, ?, ?, ?, ?)',
            [trimmedUsername, trimmedEmail, password, 'rm', 'pending']
        );

        const newUserId = insertResult.insertId;

        // Fetch the created user
        const [newUser] = await db.execute(
            'SELECT id, user_name AS username, user_email AS email, registered_at FROM users WHERE id = ?',
            [newUserId]
        );

        const newRm = newUser[0];

        // Emit real-time event to all connected admin clients
        io.emit('new_rm', {
            id: newRm.id,
            user_name: newRm.username,
            user_email: newRm.email,
            registered_at: newRm.registered_at
        });

        // Response to registering user
        res.status(201).json({
            message: 'Registration successful - Pending admin approval',
            user: newRm
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.post('/logout', express.json(), async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ error: 'Email required for logout' });
    }

    try {
        // 1. Get the user's login time
        const [result] = await db.query('SELECT login_time FROM users WHERE user_email = ?', [email]);

        const loginTime = result[0]?.login_time;
        if (!loginTime) {
            return res.status(400).json({ error: 'Login time not found for this user' });
        }

        // 2. Update logout time and session duration
        await db.query(`
            UPDATE users
            SET 
                is_logged_in = 0,
                logout_time = NOW(),
                session_duration = TIMEDIFF(NOW(), login_time)
            WHERE user_email = ?
        `, [email]);

        io.emit('logoutfromPrameshDataSystem');
        res.json({ message: '✅ User logged out successfully with session duration stored.' });
    } catch (err) {
        console.error('❌ Logout error:', err);
        res.status(500).json({ error: 'Logout failed' });
    }
});



// === 📥 API: Get Table Data ===

// === 📥 API: Get Table Data ===
// Update your backend route to include created_date
app.get('/api/getTableData/:submodule', (req, res) => {
    if (!db) {
        return res.status(503).json({ error: 'Database not connected' });
    }

    const { submodule } = req.params;

    if (!allowedTables.includes(submodule)) {
        return res.status(400).json({ error: 'Invalid table name' });
    }

    // Modified to include DATE(created_at) as created_date
    db.query(`SELECT *, DATE(created_at) as created_date FROM \`${submodule}\` WHERE is_deleted = 0 ORDER BY id DESC`)
        .then(([rows]) => {
            const formatted = rows.map(row => {
                const formattedRow = {};
                for (const key in row) {
                    if (row[key] instanceof Date) {
                        const localDate = new Date(row[key]);
                        formattedRow[key] = localDate.toLocaleDateString('en-CA');
                    } else {
                        formattedRow[key] = row[key];
                    }
                }
                // Add created_date separately if it exists
                if (row.created_date) {
                    formattedRow.created_date = row.created_date;
                }
                return formattedRow;
            });

            res.status(200).json(formatted);
        })
        .catch((error) => {
            console.error(`Error fetching data from ${submodule}:`, error);
            res.status(500).json({ error: `Failed to fetch data from ${submodule}` });
        });
});

// === 📤 API: Save Table Data ===

// For New Row Entries 
app.post('/api/insertTableData', async (req, res) => {
    const { tableName, entries } = req.body;

    if (!allowedTables.includes(tableName)) {
        return res.status(400).json({ error: 'Invalid table name' });
    }

    function normalizeDate(input) {
        if (!input) return input;
        if (typeof input === 'string') {
            const match = input.match(/^(\d{2})[-\/](\d{2})[-\/](\d{4})$/);
            if (match) {
                const [_, dd, mm, yyyy] = match;
                return `${yyyy}-${mm}-${dd}`;
            }
        }
        if (!isNaN(input) && Number(input) > 30000 && Number(input) < 60000) {
            const excelEpoch = new Date(Date.UTC(1899, 11, 30));
            const actualDate = new Date(excelEpoch.getTime() + (input * 86400000));
            return actualDate.toISOString().slice(0, 10);
        }
        return input;
    }

    try {
        const insertedRows = []; // Collect inserted rows with IDs

        // Parallelize inserts for efficiency (non-dependent operations)
        const insertPromises = entries.map(async (row) => {
            if ('id' in row) delete row.id;
            if ('created_at' in row) delete row.created_at;
            if ('updated_at' in row) delete row.updated_at;

            if (!('created_by' in row) || !row.created_by) {
                row.created_by = 'Unknown';
            }

            for (const key in row) {
                if (key.toLowerCase().includes('date') && row[key]) {
                    row[key] = normalizeDate(row[key]);
                }
            }

            const onlyDatesFilled = Object.entries(row).every(([key, val]) => {
                if (key === 'Received_Date' || key === 'Proceed_Date') return true;
                if (['Amount', 'Re_Amount', 'Total_Amount', 'Installment', 'No_of_Installment', 'Rejected_Amount'].includes(key)) {
                    return val === '0' || val === 0;
                }
                return !val || val === '' || val === null;
            });

            if (onlyDatesFilled) {
                console.log(`⛔ Skipped insert for blank row with only date fields.`);
                return null; // Skip and return null to filter later
            }

            // Add timestamps manually
            row.created_at = new Date();
            row.updated_at = new Date();

            const fields = Object.keys(row);
            const values = fields.map(f => {
                const val = row[f];
                if (typeof val === 'string' && val.trim() === '') {
                    if (f.toLowerCase().includes("date")) return null;
                }
                return val;
            });

            const escapedFields = fields.map(f => `\`${f}\``).join(', ');
            const placeholders = fields.map(() => '?').join(', ');
            const sql = `INSERT INTO \`${tableName}\` (${escapedFields}) VALUES (${placeholders})`;

            const [result] = await db.query(sql, values);
            // Return copy of row with insertId (server stores full row, but return sanitized for UI)
            return { ...row, id: result.insertId };
        });

        const results = await Promise.all(insertPromises);
        const validInsertedRows = results.filter(row => row !== null);
        const insertCount = validInsertedRows.length;

        // Emit socket event with inserted rows (only the changed/inserted ones)
        if (validInsertedRows.length > 0) {
            io.emit('rowInserted', { tableName, rows: validInsertedRows });
        }

        // Return insertedRows in response
        res.json({ success: true, inserted: insertCount, insertedRows: validInsertedRows });
    } catch (err) {
        console.error("Insert Error:", err);
        res.status(500).json({ success: false, message: "Insert failed" });
    }
});

// For Existing Row but Modified Entries 
app.put('/api/updateTableData', async (req, res) => {
    const { tableName, data } = req.body;

    if (!allowedTables.includes(tableName)) {
        return res.status(400).json({ error: 'Invalid table name' });
    }

    const { rowId, field, value, timestamp, user, submodule } = data;

    if (!rowId || !field) {
        return res.status(400).json({ error: "rowId and field are required" });
    }

    let preparedValue = value;
    const normalizedField = field.toLowerCase().replace(/_/g, ' ');
    if (
        typeof value === 'string' &&
        value.trim() === '' &&
        (normalizedField === 'proceed date' || normalizedField === 'update date' || normalizedField === 'redemption date')
    ) {
        preparedValue = null;
    }

    try {
        const sql = `UPDATE \`${tableName}\`
                        SET \`${field}\` = ?, 
                            modified_by = ?, 
                            updated_at = NOW()
                        WHERE id = ?`;

        await db.query(sql, [preparedValue, user || 'Unknown', rowId]);

        io.emit('rowUpdated', {
            tableName,
            data: { ...data, value: preparedValue }
        });

        return res.json({ success: true });

    } catch (err) {
        console.error("DB Update Error:", err);
        return res.status(500).json({ error: "Database update failed" });
    }
});

// for deleting the row 
app.delete('/api/deleteRows', async (req, res) => {
    const { tableName, ids, deleted_by } = req.body;

    if (!tableName || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "Invalid request" });
    }

    try {
        const placeholders = ids.map(() => '?').join(',');
        const query = `
            UPDATE \`${tableName}\`
            SET is_deleted = 1, deleted_by = ?, deleted_date = NOW()
            WHERE id IN (${placeholders})
        `;
        const params = [deleted_by, ...ids];

        const [result] = await db.query(query, params);

        // Emit socket event with only deleted IDs (not full table)
        io.emit('rowDeleted', { tableName, ids });

        res.json({ message: "Rows marked as deleted", affectedRows: result.affectedRows });
    } catch (err) {
        console.error("Delete error:", err);
        res.status(500).json({ message: "Failed to mark rows as deleted" });
    }
});

// for deleting all selected rows 
app.delete('/api/deleteSelectedRows', async (req, res) => {
    const { tableName, ids, deleted_by } = req.body;

    if (!tableName || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "Invalid table name or IDs" });
    }

    try {
        const placeholders = ids.map(() => '?').join(',');
        const query = `
            UPDATE \`${tableName}\`
            SET is_deleted = 1, deleted_by = ?, deleted_date = NOW()
            WHERE id IN (${placeholders})
        `;
        const params = [deleted_by, ...ids];

        const [result] = await db.query(query, params);

        // Emit socket event with only deleted IDs (not full table)
        io.emit('rowDeleted', { tableName, ids });

        res.json({ message: "Rows marked as deleted", affectedRows: result.affectedRows });
    } catch (err) {
        console.error("SQL update error:", err);
        res.status(500).json({ message: "Server error while marking rows as deleted." });
    }
});

// to get all logged Queries

app.get('/api/query-logs', async (req, res) => {
    try {
        const [logs] = await db.query(
            'SELECT user_email, endpoint, query_text, request_time FROM Query_Logs ORDER BY request_time DESC LIMIT 100'
        );
        res.json({ logs });
    } catch (err) {
        console.error('Error fetching query logs:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// GET /api/columns
app.post('/api/run-query', async (req, res) => {
    let { query } = req.body;

    if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Query is required' });
    }

    const lowerQuery = query.trim().toLowerCase();

    // ❌ Restrict access to the 'users' table (case insensitive, spaces handled)
    if (/\bfrom\s+users\b/.test(lowerQuery) || /\bjoin\s+users\b/.test(lowerQuery)) {
        return res.status(403).json({ error: 'Access to the "users" table is restricted.' });
    }

    // ❌ Allow only SELECT queries
    if (!lowerQuery.startsWith('select')) {
        return res.status(403).json({ error: 'Only SELECT queries are allowed.' });
    }

    // ✅ Automatically filter for "is_deleted = 0" in SELECT * queries
    if (lowerQuery.startsWith('select * from')) {
        const match = query.match(/select \* from\s+([^\s;]+)(.*)/i);
        if (match) {
            const tableName = match[1];
            const rest = match[2] || '';

            if (/where\s/i.test(rest)) {
                // WHERE already exists → add AND is_deleted = 0
                query = `SELECT * FROM ${tableName} ${rest.replace(/where/i, 'WHERE')} AND is_deleted = 0`;
            } else {
                // No WHERE clause
                query = `SELECT * FROM ${tableName} WHERE is_deleted = 0${rest}`;
            }
        }
    }

    try {
        const [rows] = await db.query(query);
        res.json({ rows });
    } catch (err) {
        console.error('Query execution error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.post('/api/chart-data', async (req, res) => {
    const { fromDate, duration } = req.body;
    const userEmail = req.headers['email'];

    if (!userEmail) {
        return res.status(400).json({ error: 'Missing user email' });
    }

    const from = new Date(fromDate);
    const to = new Date(from);
    to.setMonth(to.getMonth() + parseInt(duration));

    if (isNaN(from.getTime()) || isNaN(to.getTime())) {
        return res.status(400).json({ error: 'Invalid date range' });
    }

    try {
        const fromStr = from.toISOString().split('T')[0];
        const toStr = to.toISOString().split('T')[0];

        let whereClause = `Received_Date BETWEEN ? AND ? AND is_deleted = 0`;
        const params = [fromStr, toStr];

        if (!unrestricted_adminEmails.includes(userEmail)) {
            const rmName = emailToRMMap[userEmail];

            if (!rmName) {
                return res.status(403).json({ error: 'Access denied: RM not recognized' });
            }

            whereClause += ` AND RM = ?`;
            params.push(rmName);
        }

        const queries = {
            newSIP: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'SIP' AND SIP_Type = 'New' AND ${whereClause}`,
            reSIP: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Re_SIP' AND SIP_Type = 'Existing' AND ${whereClause}`,
            lumpsum: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Lumpsum' AND ${whereClause}`,
            additional: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Additional' AND ${whereClause}`,
            redemption: `SELECT SUM(Amount) as total FROM transaction WHERE Transaction_Type = 'Redemption' AND ${whereClause}`
        };

        const [sipNew] = await db.query(queries.newSIP, params);
        const [reSIP] = await db.query(queries.reSIP, params);
        const [lumpsum] = await db.query(queries.lumpsum, params);
        const [additional] = await db.query(queries.additional, params);
        const [redemption] = await db.query(queries.redemption, params);

        const amounts = {
            newSIP: Number(sipNew[0].total || 0),
            reSIP: Number(reSIP[0].total || 0),
            lumpsum: Number(lumpsum[0].total || 0),
            additional: Number(additional[0].total || 0),
            redemption: Number(redemption[0].total || 0)
        };

        const totalInvestments = amounts.newSIP + amounts.reSIP + amounts.lumpsum + amounts.additional;
        const netAmount = totalInvestments - amounts.redemption;

        const chart = {
            labels: ['New SIP', 'Re-SIP', 'Lumpsum', 'Additional', 'Redemption'],
            datasets: [{
                label: `Investment Distribution (${fromStr} to ${toStr})`,
                data: [
                    amounts.newSIP,
                    amounts.reSIP,
                    amounts.lumpsum,
                    amounts.additional,
                    amounts.redemption
                ],
                backgroundColor: ['#3f51b5', '#ff9800', '#4caf50', '#f44336', '#9c27b0']
            }]
        };

        res.json({ chart, amounts: { ...amounts, netAmount } });
    } catch (err) {
        console.error('Chart error:', err);
        res.status(500).json({ error: 'Failed to fetch chart data' });
    }
});


// Get the earliest received date for SIP or Lumpsum
app.get('/api/chart-start-date', async (req, res) => {

    try {
        const [rows] = await db.query(`
            SELECT MIN(Received_Date) as startDate
            FROM transaction
            WHERE is_deleted = 0
        `);

        const startDate = rows[0]?.startDate;

        if (!startDate) {
            return res.status(404).json({ error: 'No transactions found' });
        }

        res.json({ startDate });
    } catch (err) {
        console.error('Start date fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch start date' });
    }
});


app.get('/api/chart-overview', async (req, res) => {
    try {
        const userEmail = req.headers['email']; // Assumes email is passed in headers from frontend

        if (!userEmail) {
            return res.status(400).json({ error: 'Missing user email' });
        }

        let queryCondition = "is_deleted = 0";

        if (!unrestricted_adminEmails.includes(userEmail)) {
            const rmName = emailToRMMap[userEmail];

            if (!rmName) {
                return res.status(403).json({ error: 'Access denied: RM not recognized' });
            }

            queryCondition += ` AND RM = '${rmName}'`;
        }

        const [sipNew] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'SIP' AND SIP_Type = 'New' AND ${queryCondition}
        `);
        const [reSIP] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Re_SIP' AND SIP_Type = 'Existing' AND ${queryCondition}
        `);
        const [lumpsum] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Lumpsum' AND ${queryCondition}
        `);
        const [additional] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Additional' AND ${queryCondition}
        `);
        const [redemption] = await db.query(`
            SELECT SUM(Amount) as total FROM transaction 
            WHERE Transaction_Type = 'Redemption' AND ${queryCondition}
        `);

        const amounts = {
            newSIP: Number(sipNew[0].total || 0),
            reSIP: Number(reSIP[0].total || 0),
            lumpsum: Number(lumpsum[0].total || 0),
            additional: Number(additional[0].total || 0),
            redemption: Number(redemption[0].total || 0)
        };
        const totalInvestments = amounts.newSIP + amounts.reSIP + amounts.lumpsum + amounts.additional;
        const netAmount = totalInvestments - amounts.redemption;

        const chart = {
            labels: ['New SIP', 'Re-SIP', 'Lumpsum', 'Additional', 'Redemption'],
            datasets: [{
                label: 'Investment Overview (All Time)',
                data: [
                    amounts.newSIP,
                    amounts.reSIP,
                    amounts.lumpsum,
                    amounts.additional,
                    amounts.redemption
                ],
                backgroundColor: ['#3f51b5', '#ff9800', '#4caf50', '#f44336', '#9c27b0']
            }]
        };

        res.json({ chart, amounts: { ...amounts, netAmount } });
    } catch (err) {
        console.error("Overview chart error:", err);
        res.status(500).json({ error: "Failed to generate overview chart" });
    }
});

// UPDATED /api/client-stats TO INCLUDE RAW DATA

app.post('/api/client-stats', async (req, res) => {
    const { month, email } = req.body;

    try {
        // ---- DATE RANGE ----
        const startDate = new Date(`${month}-01`);
        const endDate = new Date(startDate.getFullYear(), startDate.getMonth() + 1, 0);
        endDate.setHours(23, 59, 59, 999);

        // ---- RM FILTER ----
        const rmName = emailToRMMap[email] || null;

        let whereClause = `
            Received_Date BETWEEN ? AND ?
            AND is_deleted = 0
            AND Client_Type != ''
        `;
        let params = [startDate, endDate];

        if (rmName) {
            whereClause += ` AND RM = ?`;
            params.push(rmName);
        }

        const query = `
            SELECT Client_Type, COUNT(*) AS count
            FROM transaction
            WHERE ${whereClause}
            GROUP BY Client_Type
        `;

        const [rows] = await db.query(query, params);

        const chart = {
            labels: rows.map(r => r.Client_Type),
            datasets: [
                {
                    label: 'Clients',
                    data: rows.map(r => r.count),
                    backgroundColor: rows.map((_, i) =>
                        ['#4caf50', '#f44336', '#2196f3', '#ff9800'][i % 4]
                    )
                }
            ]
        };

        res.json({ chart, rawData: rows });

    } catch (err) {
        console.error('Client stats error:', err);
        res.status(500).json({ error: 'Failed to fetch client stats' });
    }
});



app.post('/api/client-stats', async (req, res) => {
    const { month } = req.body;

    if (!month) return res.status(400).json({ error: "Month is required" });

    try {
        const startDate = new Date(`${month}-01`);
        const endDate = new Date();

        const [rows] = await db.query(
            `SELECT Client_Type, COUNT(*) as count
             FROM transaction
             WHERE Received_Date BETWEEN ? AND ? AND is_deleted = 0
             GROUP BY Client_Type`,
            [startDate, endDate]
        );

        const chart = {
            labels: rows.map(r => r.Client_Type),
            datasets: [{
                label: 'Clients',
                data: rows.map(r => r.count),
                backgroundColor: rows.map((_, i) => ['#4caf50', '#f44336', '#2196f3', '#ff9800'][i % 4])
            }]
        };

        res.json({ chart, rawData: rows }); // 🔧 include rawData
    } catch (err) {
        console.error('Client stats error:', err);
        res.status(500).json({ error: 'Failed to fetch client stats' });
    }
});



// for counting commision route 
app.get('/api/distinct-approach-by', async (req, res) => {
    try {
        const [prameshRows] = await db.query(
            `SELECT DISTINCT LOWER(TRIM(Approach_By)) AS name 
             FROM transaction 
             WHERE is_deleted = 0 AND Approach_By IS NOT NULL`
        );

        const [fflRows] = await db.query(
            `SELECT DISTINCT LOWER(TRIM(Approach_By)) AS name 
             FROM ffl_transaction 
             WHERE is_deleted = 0 AND Approach_By IS NOT NULL`
        );

        const uniquePramesh = [...new Set(prameshRows.map(r => r.name))];
        const uniqueFfl = [...new Set(fflRows.map(r => r.name))];

        res.json({
            pramesh: uniquePramesh,
            ffl: uniqueFfl,
        });

    } catch (err) {
        console.error('Error fetching distinct names:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Done
app.post('/api/calculate-sip-commission', async (req, res) => {
    const { approach_by, fromDate, duration, table } = req.body;
    const transactionType = "SIP";
    console.log('API called with params:', { approach_by, fromDate, duration, table, transactionType });

    if (!approach_by || !fromDate || !duration || !table) {
        console.log('Error: Missing required fields');
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        const from = new Date(fromDate);
        const to = new Date(from);
        to.setMonth(to.getMonth() + parseInt(duration) - 1);

        const targetMonth = to.getMonth();
        const targetYear = to.getFullYear();
        const lastDayOfMonth = new Date(targetYear, targetMonth + 1, 0).getDate();
        to.setDate(lastDayOfMonth);

        const fromStr = from.toISOString().split('T')[0];
        const toStr = to.toISOString().split('T')[0];

        console.log('Date range:', { fromStr, toStr });

        // Support single or multiple tables
        const tables = Array.isArray(table) ? table : [table];

        // === CASE-INSENSITIVE CHECK: Is approach_by an RM name? ===
        const rmValuesLower = Object.values(emailToRMMap).map(name => name.trim().toLowerCase());
        const approachByLower = approach_by.trim().toLowerCase();

        const applySkippingLogic = rmValuesLower.includes(approachByLower);

        if (applySkippingLogic) {
            console.log(`"${approach_by}" matches an RM name (case-insensitive) → WILL apply skipping logic (skip first 15 per month)`);
        } else {
            console.log(`"${approach_by}" does NOT match any RM name → NO skipping → commission on ALL transactions`);
        }

        // Optional: tighter query for RMs (RM = name too) — also case-insensitive safe
        const useRMFilter = applySkippingLogic;

        // Build query
        const queries = tables.map(t => {
            let whereCondition = `\`${t}\`.Approach_By = ?`;
            if (useRMFilter) {
                whereCondition = `\`${t}\`.Approach_By = ? AND \`${t}\`.RM = ?`;
            }

            return `
                SELECT 
                    \`${t}\`.RM,
                    DATE_FORMAT(\`${t}\`.Received_Date, '%d-%m-%Y') AS Date,
                    \`${t}\`.Client_Name,
                    \`${t}\`.Transaction_Type,
                    \`${t}\`.Scheme,
                    \`${t}\`.Amount,
                    \`${t}\`.Received_Date AS Original_Date
                FROM \`${t}\`
                WHERE \`${t}\`.is_deleted = 0
                  AND ${whereCondition}
                  AND \`${t}\`.Received_Date BETWEEN ? AND ?
                  AND \`${t}\`.Transaction_Type = ?
                  AND \`${t}\`.TR_status = 'success'
            `;
        }).join(" UNION ALL ");

        // Parameters (original casing used in query — DB collation should handle case if needed)
        const params = tables.flatMap(() => {
            if (useRMFilter) {
                return [approach_by, approach_by, fromStr, toStr, transactionType];
            } else {
                return [approach_by, fromStr, toStr, transactionType];
            }
        });

        // Execute query
        const [rows] = await db.query(queries, params);

        console.log(`Total raw rows fetched: ${rows.length}`);

        let finalRows = [...rows];
        let total = 0;

        // === APPLY SKIPPING ONLY IF approach_by IS AN RM (case-insensitive match) ===
        if (applySkippingLogic && rows.length > 0) {
            console.log('Applying special skipping logic: skip first 15 transactions per month');

            finalRows.sort((a, b) => new Date(a.Original_Date) - new Date(b.Original_Date));

            const rowsByMonth = {};
            finalRows.forEach(row => {
                const date = new Date(row.Original_Date);
                const monthYear = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
                if (!rowsByMonth[monthYear]) rowsByMonth[monthYear] = [];
                rowsByMonth[monthYear].push(row);
            });

            const filteredRows = [];
            Object.keys(rowsByMonth).sort().forEach(monthYear => {
                const monthRows = rowsByMonth[monthYear];
                if (monthRows.length > 15) {
                    console.log(`Month ${monthYear}: ${monthRows.length} rows → keeping ${monthRows.length - 15} after skipping first 15`);
                    filteredRows.push(...monthRows.slice(15));
                } else {
                    console.log(`Month ${monthYear}: only ${monthRows.length} rows (≤15) → skipping ALL for this month`);
                }
            });

            finalRows = filteredRows;
        } else {
            console.log('No skipping applied → using all transactions');
        }

        total = finalRows.reduce((sum, row) => sum + Number(row.Amount || 0), 0);

        finalRows = finalRows.map(({ Original_Date, ...rest }) => rest);

        console.log(`Final result → Rows: ${finalRows.length}, Total Amount: ₹${total}`);

        res.json({ total, rows: finalRows });

    } catch (err) {
        console.error('Error calculating commission:', err);
        res.status(500).json({ error: 'Failed to calculate commission' });
    }
});

app.post("/api/calculate-lumpsum-commission", async (req, res) => {
    const { approach_by, fromDate, duration, table } = req.body;
    const transactionType = "Lumpsum";

    console.log('Lumpsum API called with params:', { approach_by, fromDate, duration, table });

    if (!approach_by || !fromDate || !duration || !table) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        const from = new Date(fromDate);
        const to = new Date(from);
        to.setMonth(to.getMonth() + parseInt(duration) - 1);
        const lastDayOfMonth = new Date(to.getFullYear(), to.getMonth() + 1, 0).getDate();
        to.setDate(lastDayOfMonth);

        const fromStr = from.toISOString().split('T')[0];
        const toStr = to.toISOString().split('T')[0];

        console.log('Date range:', { fromStr, toStr });

        const tables = Array.isArray(table) ? table : [table];

        // RM Check
        const rmValuesLower = Object.values(emailToRMMap).map(name => name.trim().toLowerCase());
        const approachByLower = approach_by.trim().toLowerCase();
        const isRM = rmValuesLower.includes(approachByLower);

        const useRMFilter = isRM;

        // Fetch Lumpsum
        const lumpsumQueries = tables.map(t => {
            let where = `\`${t}\`.Approach_By = ?`;
            if (useRMFilter) where += ` AND \`${t}\`.RM = ?`;
            return `
                SELECT 
                    \`${t}\`.RM,
                    DATE_FORMAT(\`${t}\`.Received_Date, '%d-%m-%Y') AS Date,
                    \`${t}\`.Client_Name,
                    \`${t}\`.Scheme,
                    \`${t}\`.Amount,
                    \`${t}\`.Received_Date AS Original_Date,
                    \`${t}\`.Folio_Number,
                    \`${t}\`.Redemption_Date
                FROM \`${t}\`
                WHERE \`${t}\`.is_deleted = 0
                  AND ${where}
                  AND \`${t}\`.Scheme_Type != 'Debt'
                  AND \`${t}\`.Received_Date BETWEEN ? AND ?
                  AND \`${t}\`.Transaction_Type = ?
                  AND \`${t}\`.TR_status = 'Success'
            `;
        }).join(" UNION ALL ");

        const lumpsumParams = tables.flatMap(() =>
            useRMFilter
                ? [approach_by, approach_by, fromStr, toStr, transactionType]
                : [approach_by, fromStr, toStr, transactionType]
        );

        const [lumpsumRows] = await db.query(lumpsumQueries, lumpsumParams);
        console.log(`Fetched ${lumpsumRows.length} Lumpsum rows`);

        // Fetch Redemptions
        const redemptionQueries = tables.map(t => {
            let where = `\`${t}\`.Approach_By = ?`;
            if (useRMFilter) where += ` AND \`${t}\`.RM = ?`;
            return `
                SELECT 
                    Client_Name,
                    Scheme,
                    Amount AS Redemption_Amount,
                    Received_Date AS Redemption_Received_Date,
                    Redemption_Date AS Original_Investment_Date,
                    DATE_FORMAT(Received_Date, '%d-%m-%Y') AS Redemption_Display_Date,
                    DATE_FORMAT(Redemption_Date, '%d-%m-%Y') AS Investment_Date_Display
                FROM \`${t}\`
                WHERE \`${t}\`.is_deleted = 0
                  AND ${where}
                  AND \`${t}\`.Scheme_Type != 'Debt'
                  AND \`${t}\`.Received_Date BETWEEN ? AND ?
                  AND \`${t}\`.Transaction_Type = 'Redemption'
                  AND \`${t}\`.TR_status = 'Success'
            `;
        }).join(" UNION ALL ");

        const redemptionParams = tables.flatMap(() =>
            useRMFilter
                ? [approach_by, approach_by, fromStr, toStr]
                : [approach_by, fromStr, toStr]
        );

        const [redemptionRows] = await db.query(redemptionQueries, redemptionParams);
        console.log(`Fetched ${redemptionRows.length} Redemption rows`);

        let totalEligibleAmount = 0;
        let totalCommission = 0;
        let monthWiseBreakdown = [];
        let deductionDetails = [];

        const totalLumpsumAll = lumpsumRows.reduce((sum, r) => sum + Number(r.Amount || 0), 0);

        if (isRM) {
            // Group lumpsum by month
            const lumpsumByMonth = {};
            lumpsumRows.forEach(row => {
                const dt = new Date(row.Original_Date);
                const key = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
                const monthName = dt.toLocaleString('default', { month: 'long', year: 'numeric' });

                if (!lumpsumByMonth[key]) lumpsumByMonth[key] = { monthName, gross: 0 };
                lumpsumByMonth[key].gross += Number(row.Amount || 0);
            });

            // Group early redemptions by redemption processing month
            const earlyRedemptionsByMonth = {};
            redemptionRows.forEach(red => {
                const redReceivedDate = new Date(red.Redemption_Received_Date);
                const redMonthKey = `${redReceivedDate.getFullYear()}-${String(redReceivedDate.getMonth() + 1).padStart(2, '0')}`;
                const redMonthName = redReceivedDate.toLocaleString('default', { month: 'long', year: 'numeric' });

                let investmentDate = null;
                if (red.Original_Investment_Date) {
                    if (typeof red.Original_Investment_Date === 'string') {
                        const parts = red.Original_Investment_Date.split('-');
                        if (parts.length === 3) {
                            const [d, m, y] = parts.map(Number);
                            investmentDate = new Date(y, m - 1, d);
                        }
                    } else {
                        investmentDate = new Date(red.Original_Investment_Date);
                    }
                }

                if (!investmentDate || isNaN(investmentDate.getTime())) return;

                const daysDiff = (redReceivedDate - investmentDate) / (1000 * 60 * 60 * 24);

                if (daysDiff >= 0 && daysDiff < 730) {
                    if (!earlyRedemptionsByMonth[redMonthKey]) {
                        earlyRedemptionsByMonth[redMonthKey] = { monthName: redMonthName, deductions: 0, details: [] };
                    }
                    const amt = Number(red.Redemption_Amount || 0);
                    earlyRedemptionsByMonth[redMonthKey].deductions += amt;
                    earlyRedemptionsByMonth[redMonthKey].details.push({
                        clientName: red.Client_Name,
                        scheme: red.Scheme,
                        investmentDate: red.Investment_Date_Display,
                        redemptionDate: red.Redemption_Display_Date,
                        redemptionAmount: amt,
                        daysDifference: Math.floor(daysDiff)
                    });
                }
            });

            // Process each month
            Object.keys(lumpsumByMonth).sort().forEach(monthKey => {
                const month = lumpsumByMonth[monthKey];
                const deductionsThisMonth = earlyRedemptionsByMonth[monthKey]?.deductions || 0;
                const deductionInfo = earlyRedemptionsByMonth[monthKey]?.details || [];

                const netAmount = month.gross - deductionsThisMonth; // Can be negative
                const eligibleAfterThreshold = netAmount - 2500000;   // Can be negative
                const commission = eligibleAfterThreshold * 0.0015;  // Can be negative

                totalEligibleAmount += eligibleAfterThreshold;
                totalCommission += commission;

                // Save deduction details
                deductionInfo.forEach(info => {
                    deductionDetails.push({
                        month: month.monthName,
                        clientName: info.clientName,
                        scheme: info.scheme,
                        investmentDate: info.investmentDate,
                        redemptionDate: info.redemptionDate,
                        redemptionAmount: info.redemptionAmount,
                        daysDifference: info.daysDifference,
                        status: "Deducted (<2 years)"
                    });
                });

                monthWiseBreakdown.push({
                    month: month.monthName,
                    totalLumpsum: month.gross,
                    deductions: deductionsThisMonth,
                    netAmount: netAmount,
                    threshold: 2500000,
                    eligibleAfterThreshold: eligibleAfterThreshold,
                    commission: Math.round(commission),
                    status: eligibleAfterThreshold >= 0 ? "Positive (Payable)" : "Negative (Recoverable)"
                });
            });

        } else {
            // Non-RM: flat 0.15%
            totalEligibleAmount = totalLumpsumAll;
            totalCommission = totalLumpsumAll * 0.0015;

            monthWiseBreakdown.push({
                month: "All Months Combined",
                totalLumpsum: totalLumpsumAll,
                deductions: 0,
                netAmount: totalLumpsumAll,
                threshold: 0,
                eligibleAfterThreshold: totalLumpsumAll,
                commission: Math.round(totalCommission),
                status: "Flat Rate Applied"
            });
        }

        // Display rows
        const displayRows = lumpsumRows.map(row => ({
            RM: row.RM || '—',
            Date: row.Date,
            Client_Name: row.Client_Name,
            Scheme: row.Scheme,
            Amount: Number(row.Amount || 0),
            Redemption_Date: row.Redemption_Date ? formatDateFromString(row.Redemption_Date) : '—'
        }));

        res.json({
            total: Math.round(totalEligibleAmount),
            commission: Math.round(totalCommission),
            commissionRate: "0.15%",
            commissionType: isRM
                ? "RM (₹25L threshold + early redemption penalty | Negative commission recoverable)"
                : "Non-RM (0.15% flat)",
            rows: displayRows,
            monthWiseBreakdown,
            deductionDetails,
            totalLumpsum: totalLumpsumAll,
            totalRedemptions: redemptionRows.reduce((s, r) => s + Number(r.Redemption_Amount || 0), 0),
            totalDeductedAmount: deductionDetails.reduce((s, d) => s + d.redemptionAmount, 0),
            isRM
        });

    } catch (err) {
        console.error('Error calculating lumpsum commission:', err);
        res.status(500).json({ error: 'Failed to calculate commission' });
    }
});
// Helper function to format date
function formatDateFromString(dateStr) {
    if (!dateStr) return '—';
    try {
        // Handle dd-mm-yyyy format
        if (typeof dateStr === 'string' && dateStr.includes('-')) {
            const parts = dateStr.split('-');
            if (parts.length === 3) {
                const [day, month, year] = parts.map(p => parseInt(p, 10));
                const date = new Date(year, month - 1, day);
                return date.toLocaleDateString('en-GB');
            }
        }
        // Handle ISO string
        const date = new Date(dateStr);
        if (!isNaN(date.getTime())) {
            return date.toLocaleDateString('en-GB');
        }
        return '—';
    } catch (e) {
        return '—';
    }
}


app.get("/api/fetchuserdata", async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT id, user_name, user_email,password, is_logged_in FROM users where is_approved_by_admin = ?", ["approved"]
        );

        res.json({
            success: true,
            data: rows,
        });
    } catch (err) {
        console.error("Error fetching Username Password", err);
        res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }
});

app.post("/api/addDatabaseUser", async (req, res) => {
    const data = req.body;

    // 1️⃣ Basic field check
    if (!data.user_name || !data.user_email || !data.password) {
        return res.status(400).json({
            success: false,
            message: "Missing required fields: user_name, user_email, password",
        });
    }

    // 2️⃣ Additional validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?#&]).{8,}$/;

    if (data.user_name.trim().length < 3) {
        return res.status(400).json({ success: false, message: "Username must be at least 3 characters" });
    }

    if (!emailRegex.test(data.user_email)) {
        return res.status(400).json({ success: false, message: "Invalid email format" });
    }

    if (!passwordRegex.test(data.password)) {
        return res.status(400).json({
            success: false,
            message: "Password must be at least 8 characters, include uppercase, lowercase, number & special character"
        });
    }

    try {
        // 3️⃣ Check if username or email already exists
        const [existing] = await db.execute(
            "SELECT * FROM users WHERE user_name = ? OR user_email = ?",
            [data.user_name, data.user_email]
        );

        if (existing.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Username or Email already exists"
            });
        }

        // 4️⃣ Hash password
        // const hashedPassword = await bcrypt.hash(data.password, 10);

        // 5️⃣ Insert new user
        const sql = `
            INSERT INTO users 
            (user_name, user_email, password, is_logged_in, login_time, logout_time, session_duration, is_autosave_on)
            VALUES (?, ?, ?, 0, NULL, NULL, 0, 0)
        `;
        const [result] = await db.execute(sql, [
            data.user_name,
            data.user_email,
            data.password
        ]);

        res.status(201).json({
            success: true,
            message: "User added successfully",
            user_id: result.insertId
        });

    } catch (err) {
        console.error("Error Adding User", err);
        res.status(500).json({
            success: false,
            message: "Database error while adding user",
            error: err.message
        });
    }
});

app.delete('/api/deleteUser', async (req, res) => {
    const { id } = req.body;

    // Basic validation: Ensure id is provided and is a valid number
    if (!id || isNaN(id)) {
        return res.status(400).json({ success: false, message: 'Invalid or missing user ID' });
    }


    try {
        const query = 'DELETE FROM users WHERE id = ?';
        const [result] = await db.execute(query, [parseInt(id)]); // parseInt to ensure it's a number

        // Check if any rows were affected (user existed and was deleted)
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.status(200).json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, message: 'Internal server error while deleting user' });
    }
});

// Assuming you have a MySQL connection set up (e.g., using mysql2)
// const db = require('../config/database'); // Adjust path as needed; db should be a mysql2 connection or pool

app.put('/api/updateUser', async (req, res) => {
    const { id, user_name, user_email, password } = req.body;

    // Validation
    if (!id || isNaN(id)) {
        return res.status(400).json({ message: "Invalid user ID" });
    }

    if (!user_name || user_name.trim().length < 3) {
        return res.status(400).json({ message: "Username must be at least 3 characters" });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!user_email || !emailRegex.test(user_email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    // Password validation (mirror frontend logic)
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!password || !passwordRegex.test(password)) {
        return res.status(400).json({ message: "Password must be at least 8 characters, include uppercase, lowercase, number & special character" });
    }

    try {
        // Check for email uniqueness (excluding current user)
        const [existingRows] = await db.execute(
            'SELECT id FROM users WHERE user_email = ? AND id != ?',
            [user_email.toLowerCase().trim(), id]
        );
        if (existingRows.length > 0) {
            return res.status(400).json({ message: "Email already in use" });
        }

        // Update user in MySQL (saving password in plain text - WARNING: This is insecure for production; always hash passwords in real apps)
        const [updateResult] = await db.execute(
            'UPDATE users SET user_name = ?, user_email = ?, password = ? WHERE id = ?',
            [user_name.trim(), user_email.toLowerCase().trim(), password, id]
        );

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        // Fetch updated user (excluding password)
        const [userRows] = await db.execute(
            'SELECT id, user_name, user_email FROM users WHERE id = ?',
            [id]
        );
        const updatedUser = userRows[0];

        res.status(200).json({
            message: "User updated successfully",
            user: updatedUser
        });
    } catch (error) {
        console.error("Update error:", error);
        res.status(500).json({ message: "Something went wrong. Please try again!" });
    }
});

// authorising the RMs

// Updated Backend Routes with ENUM values ('pending', 'approved', 'rejected')

// GET /unauthorised_rm - Fetch pending (unauthorized) RMs
app.get('/rms', async (req, res) => {
    try {
        const { status } = req.query;
        if (!status || !['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Valid status (pending, approved, rejected) is required' });
        }

        const [rows] = await db.execute(
            'SELECT id, user_name, user_email,registered_at FROM users WHERE role = ? AND is_approved_by_admin = ?',
            ['rm', status]
        );
        res.json(rows);
    } catch (error) {
        console.error('Error fetching RMs:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /accept_rm - Approve RM (set to 'approved')
// POST /accept_rm - Approve RM (set to 'approved') + send email to RM

async function sendRmApprovalEmail(user) {
    if (!user || !user.user_email) {
        console.warn('sendRmApprovalEmail: missing user or user_email');
        return { ok: false, error: 'Missing email' };
    }
    const mailOptions = {
        from: fromAddress(),
        to: user.user_email,
        subject: '✅ Your RM account has been approved',
        text: `Hello ${user.user_name || ''},\n\nYour RM account has been approved.\n\n– Pramesh Team`,
        html: `
      <div style="font-family: Arial, sans-serif; color:#333; padding:16px;">
        <h2 style="color:#0b6ff2;">✅ RM Account Approved</h2>
        <p>Hi <strong>${user.user_name || 'User'}</strong>,</p>
        <p>Your Relationship Manager (RM) account has been <strong>approved</strong>. You can now log in using your registered email: <strong>${user.user_email}</strong></p>
        <p>If you did not register or believe this is an error, contact <a href="mailto:support@pramesh.com">support@pramesh.com</a>.</p>
        <p style="margin-top:18px;">Best regards,<br/><strong>Pramesh Team</strong></p>
        <hr/><small style="color:#666;">This is an automated message. Please do not reply.</small>
      </div>
    `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ RM approval email sent to:', user.user_email, info.response || info);
        return { ok: true, info };
    } catch (error) {
        console.error('❌ Failed to send RM approval email to', user.user_email, error);
        return { ok: false, error };
    }
}

app.post('/accept_rm', async (req, res) => {
    try {
        const { id } = req.body;
        if (!id) return res.status(400).json({ error: 'User ID is required' });

        // 1) Update user status to approved
        const [updateResult] = await db.execute(
            'UPDATE users SET is_approved_by_admin = ? WHERE id = ? AND role = ? AND is_approved_by_admin = ?',
            ['approved', id, 'rm', 'pending']
        );

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ error: 'RM not found or already approved' });
        }

        // 2) Fetch user details (name + email)
        const [userRows] = await db.execute('SELECT user_name, user_email FROM users WHERE id = ?', [id]);
        if (userRows.length === 0) {
            return res.status(404).json({ error: 'Updated RM not found' });
        }
        const user = userRows[0];

        // 3) Insert into dropdown_tags
        await db.execute(
            'INSERT INTO dropdown_tags (field_name, tag_value, created_at, updated_at, is_deleted) VALUES (?, ?, NOW(), NOW(), ?)',
            ['RM', user.user_name, 0]
        );

        // 4) Send approval email (non-blocking failure)
        if (user.user_email) {
            const mailResult = await sendRmApprovalEmail(user);
            if (!mailResult.ok) {
                console.warn('⚠️ Approval email failed for user id', id, mailResult.error);
            }
        } else {
            console.warn('⚠️ No email present for RM id:', id);
        }

        res.json({ message: 'RM approved successfully, added to dropdown_tags and approval email sent (if email exists).' });
    } catch (error) {
        console.error('Error approving RM:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// POST /reject_rm - Reject RM (set to 'rejected')
app.post('/reject_rm', async (req, res) => {

    try {
        const { id } = req.body;
        if (!id) {
            return res.status(400).json({ error: 'User ID is required' });
        }
        const [result] = await db.execute(
            'UPDATE users SET is_approved_by_admin = ? WHERE id = ? AND role = ? AND is_approved_by_admin = ?',
            ['rejected', id, 'rm', 'pending']
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'RM not found or already processed' });
        }

        res.json({ message: 'RM rejected successfully' });
    } catch (error) {
        console.error('Error rejecting RM:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// === 🚀 Start Server ===
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on ${PORT}`);
});
