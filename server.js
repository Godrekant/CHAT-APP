const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs').promises;
const multer = require('multer');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Initialize SQLite Database
const db = new sqlite3.Database('./chatapp.db', (err) => {
  if (err) {
    console.error('❌ Could not connect to SQLite database:', err.message);
  } else {
    console.log('✅ Connected to SQLite database');
    
    // Create users table if not exists
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        avatar TEXT,
        lastSeen INTEGER
      )
    `, (err) => {
      if (err) {
        console.error('❌ Table creation failed:', err.message);
      } else {
        console.log('✅ Users table ready');
      }
    });
  }
});

// In-memory storage (except users)
const onlineUsers = {}; // { socketId: username }
const chatHistory = {}; // { "user1_user2": [{ sender, content, type, timestamp, status }] }
const callRooms = {}; // { roomId: { type, participants, maxParticipants } }
const typingUsers = {}; // { "user1_user2": [typingUsernames] }

// Setup multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Serve static files
app.use(express.static(path.join(__dirname)));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/chat.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'chat.html'));
});

// Helper: Hash password
function hashPassword(password) {
  if (typeof password !== 'string') {
    throw new Error('Password must be a string');
  }
  return crypto.createHash('sha256').update(password.trim()).digest('hex');
}

// Signup route — STORES IN SQLITE
app.post('/api/signup', (req, res) => {
  let { username, password, name } = req.body;

  // Sanitize
  username = (username || '').toString().trim();
  password = (password || '').toString().trim();
  name = (name || '').toString().trim();

  if (!username || !password || !name) {
    console.log('❌ Signup failed: Missing fields', { username, password, name });
    return res.status(400).json({ error: 'All fields are required' });
  }

  const hashedPassword = hashPassword(password);
  const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random`;
  const lastSeen = Date.now();

  // Insert into SQLite
  db.run(
    `INSERT INTO users (username, password, name, avatar, lastSeen) VALUES (?, ?, ?, ?, ?)`,
    [username, hashedPassword, name, avatar, lastSeen],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          console.log('❌ Signup failed: Username exists', username);
          return res.status(400).json({ error: 'Username already exists' });
        }
        console.error('❌ SQLite insert error:', err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      console.log('✅ User created in SQLite:', username);
      res.json({ success: true, message: 'User created successfully' });
    }
  );
});

// Login route — CHECKS SQLITE
app.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  username = (username || '').toString().trim();
  password = (password || '').toString().trim();

  if (!username || !password) {
    console.log('❌ Login failed: Missing username or password', { username, password });
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const hashedInputPassword = hashPassword(password);

  // Query SQLite
  db.get(
    `SELECT username, name, avatar, password FROM users WHERE username = ?`,
    [username],
    (err, row) => {
      if (err) {
        console.error('❌ SQLite query error:', err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!row) {
        console.log('❌ Login failed: User not found', username);
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      if (row.password !== hashedInputPassword) {
        console.log('❌ Login failed: Password mismatch for user', username);
        console.log('   Input hash:', hashedInputPassword);
        console.log('   Stored hash:', row.password);
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Update lastSeen
      db.run(
        `UPDATE users SET lastSeen = ? WHERE username = ?`,
        [Date.now(), username],
        (err) => {
          if (err) console.error('Failed to update lastSeen:', err.message);
        }
      );

      console.log('✅ Login successful:', username);
      res.json({ 
        success: true, 
        user: { 
          username: row.username, 
          name: row.name, 
          avatar: row.avatar 
        } 
      });
    }
  );
});

// Search users route — QUERIES SQLITE
app.get('/api/users/search', (req, res) => {
  const { query, currentUsername } = req.query;
  
  if (!query) {
    return res.json([]);
  }

  // Search users by username or name
  const sql = `
    SELECT username, name, avatar 
    FROM users 
    WHERE username != ? 
    AND (username LIKE ? OR name LIKE ?)
    LIMIT 20
  `;
  
  const searchTerm = `%${query}%`;
  
  db.all(sql, [currentUsername, searchTerm, searchTerm], (err, rows) => {
    if (err) {
      console.error('❌ Search query error:', err.message);
      return res.status(500).json({ error: 'Search failed' });
    }

    // Add online status
    const results = rows.map(row => {
      const isOnline = Object.values(onlineUsers).includes(row.username);
      return {
        ...row,
        isOnline: isOnline
      };
    });

    res.json(results);
  });
});

// Get online users — COMBINES SQLITE + in-memory
app.get('/api/users/online', (req, res) => {
  const currentUsername = req.query.username || '';
  
  const onlineUsernames = Object.values(onlineUsers).filter(u => u !== currentUsername);
  
  if (onlineUsernames.length === 0) {
    return res.json([]);
  }

  // Get details from SQLite
  const placeholders = onlineUsernames.map(() => '?').join(',');
  const sql = `SELECT username, name, avatar FROM users WHERE username IN (${placeholders})`;
  
  db.all(sql, onlineUsernames, (err, rows) => {
    if (err) {
      console.error('❌ Online users query error:', err.message);
      return res.status(500).json({ error: 'Failed to load online users' });
    }
    res.json(rows);
  });
});

// Get chat history — STILL IN-MEMORY (you can persist later)
app.get('/api/chat/history', (req, res) => {
  const { currentUser, targetUser } = req.query;
  
  if (!currentUser || !targetUser) {
    return res.status(400).json({ error: 'Both currentUser and targetUser are required' });
  }
  
  const chatKey1 = `${currentUser}_${targetUser}`;
  const chatKey2 = `${targetUser}_${currentUser}`;
  
  let messages = [];
  if (chatHistory[chatKey1]) {
    messages = chatHistory[chatKey1];
  } else if (chatHistory[chatKey2]) {
    messages = chatHistory[chatKey2];
  }
  
  res.json(messages);
});

// File upload endpoint
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const fileName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  const fileExt = req.file.originalname.split('.').pop();
  const finalFileName = `${fileName}.${fileExt}`;
  
  const uploadDir = path.join(__dirname, 'uploads');
  
  fs.mkdir(uploadDir, { recursive: true })
    .then(() => {
      return fs.writeFile(path.join(uploadDir, finalFileName), req.file.buffer);
    })
    .then(() => {
      res.json({ 
        success: true, 
        url: `/uploads/${finalFileName}`,
        fileName: req.file.originalname,
        type: req.file.mimetype
      });
    })
    .catch(err => {
      console.error('Upload error:', err);
      res.status(500).json({ error: 'File upload failed' });
    });
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Socket.IO connection handling — UNCHANGED
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  socket.on('userLogin', (username) => {
    onlineUsers[socket.id] = username;
    socket.username = username;
    
    io.emit('userStatusChanged', {
      username: username,
      isOnline: true
    });
    
    const onlineList = Object.values(onlineUsers)
      .filter(u => u !== username)
      .map(u => ({
        username: u,
        name: 'Loading...', // Frontend will fetch details
        avatar: ''
      }));
    
    socket.emit('onlineUsers', onlineList);
  });
  
  socket.on('disconnect', () => {
    if (socket.username) {
      delete onlineUsers[socket.id];
      io.emit('userStatusChanged', {
        username: socket.username,
        isOnline: false
      });
    }
    console.log('User disconnected:', socket.id);
  });

  // === MESSAGING, TYPING, CALLS — ALL UNCHANGED ===
  // (These remain in-memory for simplicity. You can persist them later if needed.)

  socket.on('sendMessage', (data) => {
    const { sender, recipient, content, type = 'text' } = data;
    const message = {
      sender: sender,
      recipient: recipient,
      content: content,
      type: type,
      timestamp: Date.now(),
      status: 'sent'
    };
    
    const chatKey1 = `${sender}_${recipient}`;
    const chatKey2 = `${recipient}_${sender}`;
    
    if (!chatHistory[chatKey1] && !chatHistory[chatKey2]) {
      chatHistory[chatKey1] = [message];
    } else if (chatHistory[chatKey1]) {
      chatHistory[chatKey1].push(message);
    } else {
      chatHistory[chatKey2].push(message);
    }
    
    let recipientSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === recipient) {
        recipientSocketId = id;
        break;
      }
    }
    
    if (recipientSocketId) {
      message.status = 'delivered';
      
      if (chatHistory[chatKey1]) {
        chatHistory[chatKey1][chatHistory[chatKey1].length - 1].status = 'delivered';
      } else {
        chatHistory[chatKey2][chatHistory[chatKey2].length - 1].status = 'delivered';
      }
      
      io.to(recipientSocketId).emit('receiveMessage', {
        ...message,
        conversationKey: chatKey2
      });
    }
    
    socket.emit('messageSent', {
      ...message,
      conversationKey: chatKey1
    });
  });
  
  socket.on('markAsRead', (data) => {
    const { sender, recipient, messageId } = data;
    const chatKey1 = `${sender}_${recipient}`;
    const chatKey2 = `${recipient}_${sender}`;
    
    if (chatHistory[chatKey1]) {
      const messages = chatHistory[chatKey1];
      for (let i = 0; i < messages.length; i++) {
        if (messages[i].sender === sender && messages[i].status !== 'read') {
          messages[i].status = 'read';
        }
      }
    } else if (chatHistory[chatKey2]) {
      const messages = chatHistory[chatKey2];
      for (let i = 0; i < messages.length; i++) {
        if (messages[i].sender === sender && messages[i].status !== 'read') {
          messages[i].status = 'read';
        }
      }
    }
    
    let senderSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === sender) {
        senderSocketId = id;
        break;
      }
    }
    
    if (senderSocketId) {
      io.to(senderSocketId).emit('messageRead', {
        sender: sender,
        recipient: recipient,
        timestamp: Date.now()
      });
    }
  });
  
  socket.on('typing', (data) => {
    const { sender, recipient, isTyping } = data;
    const conversationKey = `${sender}_${recipient}`;
    
    if (isTyping) {
      if (!typingUsers[conversationKey]) {
        typingUsers[conversationKey] = [];
      }
      if (!typingUsers[conversationKey].includes(sender)) {
        typingUsers[conversationKey].push(sender);
      }
    } else {
      if (typingUsers[conversationKey]) {
        typingUsers[conversationKey] = typingUsers[conversationKey].filter(user => user !== sender);
        if (typingUsers[conversationKey].length === 0) {
          delete typingUsers[conversationKey];
        }
      }
    }
    
    let recipientSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === recipient) {
        recipientSocketId = id;
        break;
      }
    }
    
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('typingIndicator', {
        sender: sender,
        recipient: recipient,
        isTyping: isTyping,
        typingUsers: typingUsers[conversationKey] || []
      });
    }
  });
  
  socket.on('webrtc-offer', (data) => {
    const { roomId, sender, recipient, offer } = data;
    if (!callRooms[roomId]) {
      const maxParticipants = data.type === 'conference' ? 10 : (data.type === 'group' ? 5 : 2);
      callRooms[roomId] = {
        type: data.type || 'video',
        participants: [sender],
        maxParticipants: maxParticipants
      };
    }
    
    if (!callRooms[roomId].participants.includes(sender)) {
      if (callRooms[roomId].participants.length < callRooms[roomId].maxParticipants) {
        callRooms[roomId].participants.push(sender);
      } else {
        return socket.emit('roomFull', { roomId });
      }
    }
    
    let recipientSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === recipient) {
        recipientSocketId = id;
        break;
      }
    }
    
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('webrtc-offer-received', {
        roomId: roomId,
        sender: sender,
        offer: offer
      });
    }
  });
  
  socket.on('webrtc-answer', (data) => {
    const { roomId, sender, recipient, answer } = data;
    if (callRooms[roomId] && !callRooms[roomId].participants.includes(sender)) {
      if (callRooms[roomId].participants.length < callRooms[roomId].maxParticipants) {
        callRooms[roomId].participants.push(sender);
      } else {
        return socket.emit('roomFull', { roomId });
      }
    }
    
    let recipientSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === recipient) {
        recipientSocketId = id;
        break;
      }
    }
    
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('webrtc-answer-received', {
        roomId: roomId,
        sender: sender,
        answer: answer
      });
    }
  });
  
  socket.on('webrtc-ice-candidate', (data) => {
    const { roomId, sender, candidate, targetUser } = data;
    let targetSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === targetUser) {
        targetSocketId = id;
        break;
      }
    }
    
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-ice-candidate-received', {
        roomId: roomId,
        sender: sender,
        candidate: candidate
      });
    }
  });
  
  socket.on('join-room', (data) => {
    const { roomId, username } = data;
    if (callRooms[roomId]) {
      if (callRooms[roomId].participants.length < callRooms[roomId].maxParticipants) {
        if (!callRooms[roomId].participants.includes(username)) {
          callRooms[roomId].participants.push(username);
        }
        
        for (const participant of callRooms[roomId].participants) {
          let participantSocketId = null;
          for (const id in onlineUsers) {
            if (onlineUsers[id] === participant) {
              participantSocketId = id;
              break;
            }
          }
          
          if (participantSocketId) {
            io.to(participantSocketId).emit('user-joined-room', {
              roomId: roomId,
              username: username,
              participants: [...callRooms[roomId].participants]
            });
          }
        }
      } else {
        socket.emit('roomFull', { roomId });
      }
    }
  });
  
  socket.on('leave-room', (data) => {
    const { roomId, username } = data;
    if (callRooms[roomId]) {
      callRooms[roomId].participants = callRooms[roomId].participants.filter(p => p !== username);
      
      if (callRooms[roomId].participants.length === 0) {
        delete callRooms[roomId];
      } else {
        for (const participant of callRooms[roomId].participants) {
          let participantSocketId = null;
          for (const id in onlineUsers) {
            if (onlineUsers[id] === participant) {
              participantSocketId = id;
              break;
            }
          }
          
          if (participantSocketId) {
            io.to(participantSocketId).emit('user-left-room', {
              roomId: roomId,
              username: username,
              participants: [...callRooms[roomId].participants]
            });
          }
        }
      }
    }
  });
  
  socket.on('get-room-info', (data) => {
    const { roomId } = data;
    if (callRooms[roomId]) {
      socket.emit('room-info', {
        roomId: roomId,
        type: callRooms[roomId].type,
        participants: [...callRooms[roomId].participants],
        maxParticipants: callRooms[roomId].maxParticipants
      });
    } else {
      socket.emit('room-not-found', { roomId });
    }
  });
});

// Create uploads directory
fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true }).catch(console.error);

// Close DB on process exit
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('❌ Error closing SQLite database:', err.message);
    } else {
      console.log('✅ SQLite database closed');
    }
    process.exit(0);
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('🔐 Users now stored in SQLite (chatapp.db)');
  console.log('📱 Perfect for Termux — data persists after restart!');
});
