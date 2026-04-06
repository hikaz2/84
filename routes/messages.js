const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../database/init');
const { requireAuth } = require('../middleware/auth');

// GET /mesajlar - Conversations list
router.get('/', requireAuth, (req, res) => {
  db.all(`
    SELECT c.*, 
      u1.username as user1_username, u1.avatar as user1_avatar,
      u2.username as user2_username, u2.avatar as user2_avatar,
      l.title as listing_title, l.uuid as listing_uuid
    FROM conversations c
    JOIN users u1 ON c.user1_id = u1.id
    JOIN users u2 ON c.user2_id = u2.id
    LEFT JOIN listings l ON c.listing_id = l.id
    WHERE c.user1_id = ? OR c.user2_id = ?
    ORDER BY c.last_message_at DESC NULLS LAST
  `, [req.user.id, req.user.id], (err, conversations) => {
    res.render('messages/index', {
      title: 'Mesajlarım',
      conversations: (conversations || []).map(c => ({
        ...c,
        otherUser: c.user1_id === req.user.id ? { username: c.user2_username, avatar: c.user2_avatar } : { username: c.user1_username, avatar: c.user1_avatar },
        unreadCount: c.user1_id === req.user.id ? c.user1_unread : c.user2_unread
      }))
    });
  });
});

// GET /mesajlar/:uuid - View conversation
router.get('/:uuid', requireAuth, (req, res) => {
  db.get(`
    SELECT c.*, 
      u1.username as user1_username, u1.avatar as user1_avatar,
      u2.username as user2_username, u2.avatar as user2_avatar,
      l.title as listing_title, l.uuid as listing_uuid, l.price as listing_price
    FROM conversations c
    JOIN users u1 ON c.user1_id = u1.id
    JOIN users u2 ON c.user2_id = u2.id
    LEFT JOIN listings l ON c.listing_id = l.id
    WHERE c.uuid = ? AND (c.user1_id = ? OR c.user2_id = ?)
  `, [req.params.uuid, req.user.id, req.user.id], (err, conversation) => {
    if (!conversation) return res.redirect('/mesajlar');

    const otherUser = conversation.user1_id === req.user.id
      ? { id: conversation.user2_id, username: conversation.user2_username, avatar: conversation.user2_avatar }
      : { id: conversation.user1_id, username: conversation.user1_username, avatar: conversation.user1_avatar };

    // Mark messages as read
    db.run(`UPDATE messages SET is_read = 1 WHERE conversation_id = ? AND receiver_id = ?`,
      [conversation.uuid, req.user.id]);

    // Reset unread count
    if (conversation.user1_id === req.user.id) {
      db.run(`UPDATE conversations SET user1_unread = 0 WHERE uuid = ?`, [conversation.uuid]);
    } else {
      db.run(`UPDATE conversations SET user2_unread = 0 WHERE uuid = ?`, [conversation.uuid]);
    }

    db.all(`SELECT m.*, u.username, u.avatar FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.conversation_id = ? ORDER BY m.created_at ASC`,
      [conversation.uuid], (err, messages) => {
      res.render('messages/conversation', {
        title: `${otherUser.username} ile Mesajlar`,
        conversation, messages: messages || [], otherUser,
        listing: conversation.listing_uuid ? { uuid: conversation.listing_uuid, title: conversation.listing_title, price: conversation.listing_price } : null
      });
    });
  });
});

// POST /mesajlar/yeni - Start new conversation
router.post('/yeni', requireAuth, (req, res) => {
  const { receiver_id, listing_uuid, message } = req.body;
  if (!receiver_id || !message) return res.redirect('/mesajlar');
  if (parseInt(receiver_id) === req.user.id) return res.redirect('/mesajlar');

  db.get(`SELECT id FROM users WHERE id = ?`, [receiver_id], (err, receiver) => {
    if (!receiver) return res.redirect('/mesajlar');

    const findQuery = `
      SELECT * FROM conversations WHERE 
      ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
    `;
    const listingClause = listing_uuid ? ` AND listing_id = (SELECT id FROM listings WHERE uuid = '${listing_uuid}')` : '';

    db.get(findQuery + (listing_uuid ? listingClause : ' AND listing_id IS NULL'), 
      [req.user.id, receiver_id, receiver_id, req.user.id], (err, conv) => {
      const sendMessage = (convUuid) => {
        db.run(`INSERT INTO messages (conversation_id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)`,
          [convUuid, req.user.id, receiver_id, message]);
        
        // Update conversation last message & unread
        db.get(`SELECT * FROM conversations WHERE uuid = ?`, [convUuid], (err, c) => {
          if (c) {
            if (c.user1_id === req.user.id) {
              db.run(`UPDATE conversations SET last_message=?, last_message_at=datetime('now'), user2_unread=user2_unread+1 WHERE uuid=?`, [message, convUuid]);
            } else {
              db.run(`UPDATE conversations SET last_message=?, last_message_at=datetime('now'), user1_unread=user1_unread+1 WHERE uuid=?`, [message, convUuid]);
            }
          }
        });

        // Send notification
        db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'message', 'Yeni Mesaj', ?, ?)`,
          [receiver_id, `${req.user.username} size bir mesaj gönderdi.`, `/mesajlar/${convUuid}`]);

        res.redirect(`/mesajlar/${convUuid}`);
      };

      if (conv) {
        sendMessage(conv.uuid);
      } else {
        const convUuid = uuidv4();
        let listingId = null;
        const createConv = () => {
          db.run(`INSERT INTO conversations (uuid, user1_id, user2_id, listing_id) VALUES (?, ?, ?, ?)`,
            [convUuid, req.user.id, receiver_id, listingId], () => sendMessage(convUuid));
        };
        
        if (listing_uuid) {
          db.get(`SELECT id FROM listings WHERE uuid = ?`, [listing_uuid], (err, l) => {
            listingId = l ? l.id : null;
            createConv();
          });
        } else {
          createConv();
        }
      }
    });
  });
});

// POST /mesajlar/:uuid/gonder - Send message in conversation
router.post('/:uuid/gonder', requireAuth, (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.redirect(`/mesajlar/${req.params.uuid}`);

  db.get(`SELECT * FROM conversations WHERE uuid = ? AND (user1_id = ? OR user2_id = ?)`,
    [req.params.uuid, req.user.id, req.user.id], (err, conv) => {
    if (!conv) return res.redirect('/mesajlar');

    const receiverId = conv.user1_id === req.user.id ? conv.user2_id : conv.user1_id;
    db.run(`INSERT INTO messages (conversation_id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)`,
      [conv.uuid, req.user.id, receiverId, message.trim()]);

    if (conv.user1_id === req.user.id) {
      db.run(`UPDATE conversations SET last_message=?, last_message_at=datetime('now'), user2_unread=user2_unread+1 WHERE uuid=?`, [message.trim(), conv.uuid]);
    } else {
      db.run(`UPDATE conversations SET last_message=?, last_message_at=datetime('now'), user1_unread=user1_unread+1 WHERE uuid=?`, [message.trim(), conv.uuid]);
    }

    db.run(`INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, 'message', 'Yeni Mesaj', ?, ?)`,
      [receiverId, `${req.user.username} size bir mesaj gönderdi.`, `/mesajlar/${conv.uuid}`]);

    res.redirect(`/mesajlar/${conv.uuid}`);
  });
});

module.exports = router;
