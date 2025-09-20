const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs').promises;
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// In-memory storage (except users - now in JSON)
let users = {}; // Will load from users.json
const onlineUsers = {};
const chatHistory = {};
const callRooms = {};
const typingUsers = {};

// Load users from JSON file on startup
async function loadUsers() {
  try {
    const data = await fs.readFile(path.join(__dirname, 'users.json'), 'utf8');
    users = JSON.parse(data);
    console.log('✅ Loaded users from JSON file');
  } catch (err) {
    console.log('⚠️ No users.json found or invalid JSON - starting fresh');
    users = {};
  }
}

// Save users to JSON file
async function saveUsers() {
  try {
    await fs.writeFile(path.join(__dirname, 'users.json'), JSON.stringify(users, null, 2));
    console.log('💾 Users saved to JSON file');
  } catch (err) {
    console.error('❌ Failed to save users:', err.message);
  }
}

// Setup multer
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Middleware
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

// Signup route
app.post('/api/signup', async (req, res) => {
  console.log('========================================');
  console.log('🚀 SIGNUP ATTEMPT');
  console.log('========================================');
  
  let { username, password, name } = req.body;

  username = username ? String(username).trim() : '';
  password = password ? String(password).trim() : '';
  name = name ? String(name).trim() : '';

  console.log('📝 Input:', { username, password, name });

  if (!username || !password || !name) {
    console.log('❌ Missing fields');
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (users[username]) {
    console.log('❌ Username exists:', username);
    return res.status(400).json({ error: 'Username already exists' });
  }

  const hashedPassword = hashPassword(password);
  const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random`;
  const lastSeen = Date.now();

  users[username] = {
    password: hashedPassword,
    name: name,
    avatar: avatar,
    lastSeen: lastSeen
  };

  try {
    await saveUsers();
    console.log('✅ User created:', username);
    res.json({ success: true, message: 'User created successfully' });
  } catch (err) {
    console.log('❌ Save failed:', err.message);
    res.status(500).json({ error: 'Failed to save user' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  console.log('========================================');
  console.log('🚀 LOGIN ATTEMPT');
  console.log('========================================');
  
  let { username, password } = req.body;

  username = username ? String(username).trim() : '';
  password = password ? String(password).trim() : '';

  console.log('📝 Input:', { username, password });

  if (!username || !password) {
    console.log('❌ Missing fields');
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users[username];
  if (!user) {
    console.log('❌ User not found:', username);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const hashedInputPassword = hashPassword(password);

  console.log('🔑 Input hash:', hashedInputPassword);
  console.log('🔑 Stored hash:', user.password);

  if (user.password !== hashedInputPassword) {
    console.log('❌ Password mismatch');
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Update lastSeen
  user.lastSeen = Date.now();
  try {
    await saveUsers();
  } catch (err) {
    console.error('⚠️ Failed to update lastSeen:', err.message);
  }

  console.log('✅ Login successful:', username);
  res.json({ 
    success: true, 
    user: { 
      username: user.username, 
      name: user.name, 
      avatar: user.avatar 
    } 
  });
});

// Search users
app.get('/api/users/search', (req, res) => {
  const { query, currentUsername } = req.query;
  
  if (!query) {
    return res.json([]);
  }

  const results = [];
  for (const username in users) {
    if (username !== currentUsername && 
        (username.toLowerCase().includes(query.toLowerCase()) || 
         users[username].name.toLowerCase().includes(query.toLowerCase()))) {
      results.push({
        username: username,
        name: users[username].name,
        avatar: users[username].avatar,
        isOnline: !!Object.values(onlineUsers).find(u => u === username)
      });
    }
  }
  
  res.json(results);
});

// Get online users
app.get('/api/users/online', (req, res) => {
  const onlineList = [];
  const currentUsername = req.query.username;
  
  for (const socketId in onlineUsers) {
    const username = onlineUsers[socketId];
    if (username !== currentUsername) {
      onlineList.push({
        username: username,
        name: users[username].name,
        avatar: users[username].avatar
      });
    }
  }
  
  res.json(onlineList);
});

// Get chat history
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

// File upload
app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const fileName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  const fileExt = req.file.originalname.split('.').pop();
  const finalFileName = `${fileName}.${fileExt}`;
  
  const uploadDir = path.join(__dirname, 'uploads');
  
  try {
    await fs.mkdir(uploadDir, { recursive: true });
    await fs.writeFile(path.join(uploadDir, finalFileName), req.file.buffer);
    
    res.json({ 
      success: true, 
      url: `/uploads/${finalFileName}`,
      fileName: req.file.originalname,
      type: req.file.mimetype
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Socket.IO connection handling
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
        name: users[u].name,
        avatar: users[u].avatar
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

  // === ALL OTHER SOCKET EVENTS REMAIN THE SAME ===
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

// Load users on startup
loadUsers().then(() => {
  // Start server
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log('💾 Users stored in users.json');
    console.log('📱 Perfect for Termux - data persists!');
  });
});
