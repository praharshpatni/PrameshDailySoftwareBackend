// module.exports = router;
const express = require('express');
const router = express.Router();

let dbPool = require('./../DatabaseConnection/dbConfig');
let io;
// Shared state for real-time chat features
const onlineUsers = new Map();
const userSockets = new Map();
const activeChats = new Map();

// Function to initialize sockets and db
const initializeChat = (socketIO) => {
    io = socketIO;
    // === Socket.IO Real-Time Chat Logic ===
    io.on('connection', (socket) => {
        console.log('New client connected:', socket.id);

        // User logs in (joins chat system)
        socket.on('login', async (userEmail) => {
            if (!userEmail) return;

            onlineUsers.set(socket.id, userEmail);
            userSockets.set(userEmail, socket.id);

            try {
                await dbPool.execute(
                    'UPDATE users SET is_logged_in = 1 WHERE user_email = ?',
                    [userEmail]
                );
            } catch (err) {
                console.error('Error setting user online:', err);
            }

            // Notify everyone this user is now online
            io.emit('userStatus', { userEmail, online: true });
        });

        // Track which chat the user is currently viewing
        socket.on('setActiveChat', ({ userEmail, activeChatEmail }) => {
            console.log(`User ${userEmail} is now viewing chat with ${activeChatEmail || 'none'}`);

            if (activeChatEmail) {
                activeChats.set(userEmail, activeChatEmail);
            } else {
                activeChats.delete(userEmail);
            }
        });

        // Send a new message
        socket.on('sendMessage', async ({ senderEmail, receiverEmail, messageText, replyToId }) => {
            if (!senderEmail || !receiverEmail || !messageText.trim()) return;

            try {
                const receiverActiveChat = activeChats.get(receiverEmail);
                const isReceiverViewingSenderChat = receiverActiveChat === senderEmail;

                console.log(`\n📨 Message from ${senderEmail} → ${receiverEmail}`);
                console.log(`Receiver viewing this chat? ${isReceiverViewingSenderChat ? 'YES' : 'NO'}`);

                let insertQuery, insertParams;

                if (isReceiverViewingSenderChat) {
                    insertQuery = `
                        INSERT INTO messages 
                        (sender_email, receiver_email, message_text, reply_to_id, sent_at, read_at)
                        VALUES (?, ?, ?, ?, NOW(), NOW())
                    `;
                    insertParams = [senderEmail, receiverEmail, messageText.trim(), replyToId || null];
                } else {
                    insertQuery = `
                        INSERT INTO messages 
                        (sender_email, receiver_email, message_text, reply_to_id, sent_at)
                        VALUES (?, ?, ?, ?, NOW())
                    `;
                    insertParams = [senderEmail, receiverEmail, messageText.trim(), replyToId || null];
                }

                const [result] = await dbPool.execute(insertQuery, insertParams);

                // Fetch the full message with reply info
                const [rows] = await dbPool.execute(
                    `SELECT m.*, 
                            r.message_text AS reply_text, 
                            r.sender_email AS reply_sender_email
                     FROM messages m
                     LEFT JOIN messages r ON m.reply_to_id = r.id
                     WHERE m.id = ?`,
                    [result.insertId]
                );

                const message = rows[0];

                // Send to sender and receiver
                const senderSocket = userSockets.get(senderEmail);
                const receiverSocket = userSockets.get(receiverEmail);

                if (senderSocket) {
                    io.to(senderSocket).emit('newMessage', message);
                }
                if (receiverSocket) {
                    io.to(receiverSocket).emit('newMessage', message);
                    await dbPool.execute(
                        'UPDATE messages SET delivered_at = NOW() WHERE id = ?',
                        [message.id]
                    );
                }

                console.log(`Message delivered (read: ${!!message.read_at})`);
            } catch (err) {
                console.error('Error sending message:', err);
            }
        });

        // Typing indicator
        socket.on('typing', ({ toUserEmail, isTyping }) => {
            const socketId = userSockets.get(toUserEmail);
            if (socketId) {
                io.to(socketId).emit('userTyping', {
                    fromUserEmail: onlineUsers.get(socket.id),
                    isTyping
                });
            }
        });

        // Optional: Keep your global data update event
        socket.on('new_data', (data) => {
            console.log('Received new_data:', data);
            io.emit('update_data', data);
        });

        // Disconnect handling
        socket.on('disconnect', async () => {
            const userEmail = onlineUsers.get(socket.id);
            if (userEmail) {
                activeChats.delete(userEmail);
                onlineUsers.delete(socket.id);
                userSockets.delete(userEmail);

                try {
                    await dbPool.execute(
                        'UPDATE users SET is_logged_in = 0 WHERE user_email = ?',
                        [userEmail]
                    );
                } catch (err) {
                    console.error('Error setting user offline:', err);
                }

                io.emit('userStatus', { userEmail, online: false });
                console.log(`User ${userEmail} disconnected`);
            }
            console.log('Client disconnected:', socket.id);
        });
    });
};

// =========================================
// HTTP Routes for Chat
// =========================================

// Fetch active/approved users + last message preview for each conversation
// router.get("/fetchActiveUsers", async (req, res) => {
//     try {
//         const { currentUserEmail } = req.query;

//         if (!currentUserEmail) {
//             return res.status(400).json({
//                 success: false,
//                 message: "currentUserEmail is required"
//             });
//         }

//         const sql = `
//     SELECT 
//         u.id,
//         u.user_name,
//         u.user_email,
//         u.role,
//         u.is_logged_in,
//         lm.message_text AS last_message,
//         lm.sender_email AS last_message_sender,
//         lm.sent_at AS last_message_time,
//         lm.is_deleted AS last_message_is_deleted
//     FROM users u
//     LEFT JOIN (
//         SELECT 
//             m1.message_text,
//             m1.sender_email,
//             m1.receiver_email,
//             m1.sent_at,
//             m1.is_deleted  -- Only select what you need, including is_deleted
//         FROM messages m1
//         INNER JOIN (
//             SELECT 
//                 CASE 
//                     WHEN sender_email = ? THEN receiver_email 
//                     ELSE sender_email 
//                 END AS other_user,
//                 MAX(sent_at) AS max_time
//             FROM messages
//             WHERE sender_email = ? OR receiver_email = ?
//             GROUP BY other_user
//         ) m2 ON (
//             (m1.sender_email = ? AND m1.receiver_email = m2.other_user) OR
//             (m1.receiver_email = ? AND m1.sender_email = m2.other_user)
//         ) AND m1.sent_at = m2.max_time
//     ) lm ON (
//         (lm.sender_email = ? AND lm.receiver_email = u.user_email) OR
//         (lm.receiver_email = ? AND lm.sender_email = u.user_email)
//     )
//     WHERE u.user_email != ? 
//       AND u.is_approved_by_admin = "approved"
//     ORDER BY 
//         u.is_logged_in DESC,
//         lm.sent_at DESC,
//         u.user_name ASC
// `;

//         const params = [
//             currentUserEmail, currentUserEmail, currentUserEmail,
//             currentUserEmail, currentUserEmail,
//             currentUserEmail, currentUserEmail,
//             currentUserEmail
//         ];

//         const [rows] = await dbPool.query(sql, params);

//         const users = rows.map(row => ({
//             id: row.id,
//             user_name: row.user_name,
//             user_email: row.user_email,
//             role: row.role,
//             is_logged_in: row.is_logged_in,
//             last_message: row.last_message ? {
//                 message_text: row.last_message,
//                 is_deleted: row.last_message_is_deleted || 0  // Include is_deleted as number (0 or 1)
//             } : null,
//             last_message_sender: row.last_message_sender || null,
//             last_message_time: row.last_message_time || null
//         }));

//         res.status(200).json({
//             success: true,
//             users
//         });

//     } catch (error) {
//         console.error("Error fetching active users with last message:", error);
//         res.status(500).json({
//             success: false,
//             message: "Server error",
//             error: error.message
//         });
//     }
// });
router.get("/fetchActiveUsers", async (req, res) => {
    try {
        const { currentUserEmail } = req.query;

        if (!currentUserEmail) {
            return res.status(400).json({
                success: false,
                message: "currentUserEmail is required"
            });
        }

        const sql = `
            SELECT 
                u.id,
                u.user_name,
                u.user_email,
                u.role,
                u.is_logged_in,
                lm.message_text AS last_message,
                lm.sender_email AS last_message_sender,
                lm.sent_at AS last_message_time,
                lm.is_deleted AS last_message_is_deleted  -- Separate field
            FROM users u
            LEFT JOIN (
                SELECT 
                    m1.message_text,
                    m1.sender_email,
                    m1.receiver_email,
                    m1.sent_at,
                    m1.is_deleted
                FROM messages m1
                INNER JOIN (
                    SELECT 
                        CASE 
                            WHEN sender_email = ? THEN receiver_email 
                            ELSE sender_email 
                        END AS other_user,
                        MAX(sent_at) AS max_time
                    FROM messages
                    WHERE sender_email = ? OR receiver_email = ?
                    GROUP BY other_user
                ) m2 ON (
                    (m1.sender_email = ? AND m1.receiver_email = m2.other_user) OR
                    (m1.receiver_email = ? AND m1.sender_email = m2.other_user)
                ) AND m1.sent_at = m2.max_time
            ) lm ON (
                (lm.sender_email = ? AND lm.receiver_email = u.user_email) OR
                (lm.receiver_email = ? AND lm.sender_email = u.user_email)
            )
            WHERE u.user_email != ? 
              AND u.is_approved_by_admin = "approved"
            ORDER BY 
                u.is_logged_in DESC,
                lm.sent_at DESC,
                u.user_name ASC
        `;

        const params = [
            currentUserEmail, currentUserEmail, currentUserEmail,
            currentUserEmail, currentUserEmail,
            currentUserEmail, currentUserEmail,
            currentUserEmail
        ];

        const [rows] = await dbPool.query(sql, params);

        const users = rows.map(row => ({
            id: row.id,
            user_name: row.user_name,
            user_email: row.user_email,
            role: row.role,
            is_logged_in: row.is_logged_in,
            last_message: row.last_message || null,                    // Simple string or null
            last_message_sender: row.last_message_sender || null,
            last_message_time: row.last_message_time || null,
            last_message_is_deleted: row.last_message_is_deleted || 0   // Separate field: 0 or 1
        }));

        res.status(200).json({
            success: true,
            users
        });

    } catch (error) {
        console.error("Error fetching active users with last message:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message
        });
    }
});

// Fetch chat messages between two users
router.get("/messages", async (req, res) => {
    const { currentUserEmail, otherUserEmail } = req.query;

    if (!currentUserEmail || !otherUserEmail) {
        return res.status(400).json({ error: "Both emails required" });
    }

    try {
        const [rows] = await dbPool.execute(
            `SELECT m.*, 
                    r.message_text AS reply_text, 
                    r.sender_email AS reply_sender_email
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
        res.status(500).json({ error: "Server error" });
    }
});

// Get unread counts + last message time for all conversations
router.get("/unread-counts", async (req, res) => {
    const { currentUserEmail } = req.query;

    if (!currentUserEmail) {
        return res.status(400).json({ error: "Missing currentUserEmail" });
    }

    try {
        const [rows] = await dbPool.execute(`
            SELECT
                other_user_email,
                COUNT(CASE WHEN receiver_email = ? AND read_at IS NULL THEN 1 END) AS unread_count,
                MAX(sent_at) AS last_message_time
            FROM (
                SELECT
                    CASE WHEN sender_email = ? THEN receiver_email ELSE sender_email END AS other_user_email,
                    sent_at, receiver_email, read_at
                FROM messages
                WHERE sender_email = ? OR receiver_email = ?
            ) AS subquery
            GROUP BY other_user_email
        `, [currentUserEmail, currentUserEmail, currentUserEmail, currentUserEmail]);

        const unreadCounts = {};
        const lastMessageTimes = {};

        rows.forEach(row => {
            unreadCounts[row.other_user_email] = parseInt(row.unread_count) || 0;
            lastMessageTimes[row.other_user_email] = row.last_message_time;
        });

        res.json({ unreadCounts, lastMessageTimes });
    } catch (err) {
        console.error("Error fetching unread counts:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// Mark messages as read
router.post("/mark-as-read", async (req, res) => {
    const { currentUserEmail, otherUserEmail } = req.body;

    if (!currentUserEmail || !otherUserEmail) {
        return res.status(400).json({ error: "Missing emails" });
    }

    try {
        await dbPool.execute(`
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


router.post('/edit-message', async (req, res) => {
    const { messageId, newText, currentUserEmail } = req.body;
    try {
        // Fetch sender_email and receiver_email to verify ownership and get receiver
        const [rows] = await dbPool.query(
            `SELECT sender_email, receiver_email FROM messages WHERE id = ?`,
            [messageId]
        );

        if (rows.length === 0) {
            return res.json({ success: false, error: "Message not found" });
        }

        const message = rows[0];

        // Verify that the current user is the sender (only sender can edit)
        if (message.sender_email !== currentUserEmail) {
            return res.json({ success: false, error: "Unauthorized" });
        }

        const receiverEmail = message.receiver_email;

        // Update the message in the database
        await dbPool.query(
            `UPDATE messages SET message_text = ?, edited = 1 WHERE id = ?`,
            [newText.trim(), messageId]
        );

        // Prepare data to send via socket
        const editedMessageData = {
            messageId,
            newText: newText.trim(),
            edited: true
        };

        // Emit to the sender (current user who edited)
        console.log("edited message data ")
        io.emit('messageEdited', editedMessageData);
        res.json({ success: true });
    } catch (err) {
        console.error("Error editing message:", err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// Delete message (soft delete)
router.post('/delete-message', async (req, res) => {
    const { messageId, currentUserEmail } = req.body;

    try {
        // First verify the message belongs to the user
        const [message] = await dbPool.query(
            `SELECT sender_email, receiver_email FROM messages WHERE id = ?`,
            [messageId]
        );

        if (message.length === 0) {
            return res.json({ success: false, error: "Message not found" });
        }

        const msg = message[0];

        // Verify that the current user is the sender (only sender can delete)
        if (msg.sender_email !== currentUserEmail) {
            return res.json({ success: false, error: "Unauthorized" });
        }

        // Soft delete by setting is_deleted = 1
        await dbPool.query(
            `UPDATE messages SET is_deleted = 1 WHERE id = ?`,
            [messageId]
        );

        // Emit socket event to notify the receiver
        const deleteMessageData = {
            messageId,
            isDeleted: true
        };

        // Emit to both sender and receiver
        io.emit('messageDeleted', deleteMessageData);

        res.json({ success: true });
    } catch (err) {
        console.error("Error deleting message:", err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// Export router AND the initializer function
module.exports = {
    router,
    initializeChat
};