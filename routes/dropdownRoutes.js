require('dotenv').config();
const express = require('express');
const router = express.Router();

const mysql = require('mysql2/promise');

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


router.get('/dropdowns', async (req, res) => {
    try {
        // console.log("requested for the dropdown data");
        const [results] = await db.query('SELECT field_name, tag_value FROM dropdown_tags WHERE is_deleted = 0');
        const grouped = {};
        results.forEach(({ field_name, tag_value }) => {
            if (!grouped[field_name]) grouped[field_name] = [];
            grouped[field_name].push(tag_value);
        });
        // console.log("grouped", grouped)
        res.json(grouped);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database fetch failed' });
    }
});

// === Add option (avoid duplicates, revive if soft deleted) ===
router.post('/dropdowns/add', async (req, res) => {
    const { field, value } = req.body;
    try {
        const [existing] = await db.query(
            'SELECT * FROM dropdown_tags WHERE field_name = ? AND tag_value = ?',
            [field, value]
        );

        if (existing.length > 0) {
            if (existing[0].is_deleted === 0) {
                return res.status(400).json({ error: 'Value already exists in this field' });
            } else {
                await db.query(
                    'UPDATE dropdown_tags SET is_deleted = 0 WHERE field_name = ? AND tag_value = ?',
                    [field, value]
                );
                return res.json({ success: true, message: 'Value restored' });
            }
        }

        await db.query('INSERT INTO dropdown_tags (field_name, tag_value) VALUES (?, ?)', [field, value]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// === Soft Delete option ===
router.delete('/dropdowns/delete', async (req, res) => {
    const { field, value } = req.body;
    try {
        await db.query(
            'UPDATE dropdown_tags SET is_deleted = 1 WHERE field_name = ? AND tag_value = ?',
            [field, value]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// === Rename option ===
router.put('/dropdowns/rename', async (req, res) => {
    const { field, oldValue, newValue } = req.body;
    try {
        const [check] = await db.query(
            'SELECT * FROM dropdown_tags WHERE field_name = ? AND tag_value = ? AND is_deleted = 0',
            [field, newValue]
        );

        if (check.length > 0) {
            return res.status(400).json({ error: 'New value already exists in this field' });
        }

        await db.query(
            'UPDATE dropdown_tags SET tag_value = ? WHERE field_name = ? AND tag_value = ?',
            [newValue, field, oldValue]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
module.exports = router;
