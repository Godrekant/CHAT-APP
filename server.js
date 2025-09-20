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

// In-memory storage
const users = {}; // { username: { password, name, avatar, lastSeen } }
const onlineUsers = {}; // { socketId: username }
const chatHistory = {}; // { "user1_user2": [{ sender, content, type, timestamp, status }] }
const callRooms = {}; // { roomId: { type: 'voice' | 'video' | 'group' | 'conference', participants: [], maxParticipants } }
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
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Signup route — FIXED
app.post('/api/signup', async (req, res) => {
  const { username, password, name } = req.body;
  
  // Validate input
  if (!username || !password || !name) {
    console.log('Signup failed: Missing fields', { username, password, name });
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  // Check if user exists
  if (users[username]) {
    console.log('Signup failed: User exists', username);
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  try {
    // Hash password
    const hashedPassword = hashPassword(password);
    
    // Create user
    users[username] = {
      password: hashedPassword,
      name: name,
      avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random`,
      lastSeen: Date.now()
    };
    
    console.log('User created:', username);
    res.json({ success: true, message: 'User created successfully' });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login route — FIXED
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Validate input
  if (!username || !password) {
    console.log('Login failed: Missing username or password', { username, password });
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  const user = users[username];
  if (!user) {
    console.log('Login failed: User not found', username);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  
  try {
    // Hash the input password
    const hashedInputPassword = hashPassword(password);
    
    // Compare with stored hash
    if (user.password !== hashedInputPassword) {
      console.log('Login failed: Password mismatch for user', username);
      console.log('Input hash:', hashedInputPassword);
      console.log('Stored hash:', user.password);
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // Update last seen
    user.lastSeen = Date.now();
    
    console.log('Login successful:', username);
    res.json({ 
      success: true, 
      user: { 
        username: username, 
        name: user.name, 
        avatar: user.avatar 
      } 
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Search users route
app.get('/api/users/search', (req, res) => {
  const { query, currentUsername } = req.query;
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

// Get chat history for a conversation
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
  
  // Generate a unique filename
  const fileName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  const fileExt = req.file.originalname.split('.').pop();
  const finalFileName = `${fileName}.${fileExt}`;
  
  // Save file to uploads directory
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

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // User login event
  socket.on('userLogin', (username) => {
    onlineUsers[socket.id] = username;
    socket.username = username;
    
    // Notify all users about online status change
    io.emit('userStatusChanged', {
      username: username,
      isOnline: true
    });
    
    // Send current online users to the newly connected user
    const onlineList = Object.values(onlineUsers)
      .filter(u => u !== username)
      .map(u => ({
        username: u,
        name: users[u].name,
        avatar: users[u].avatar
      }));
    
    socket.emit('onlineUsers', onlineList);
  });
  
  // User logout/disconnect
  socket.on('disconnect', () => {
    if (socket.username) {
      delete onlineUsers[socket.id];
      
      // Notify all users about online status change
      io.emit('userStatusChanged', {
        username: socket.username,
        isOnline: false
      });
    }
    console.log('User disconnected:', socket.id);
  });
  
  // Send message
  socket.on('sendMessage', (data) => {
    const { sender, recipient, content, type = 'text' } = data;
    
    // Create message object
    const message = {
      sender: sender,
      recipient: recipient,
      content: content,
      type: type,
      timestamp: Date.now(),
      status: 'sent'
    };
    
    // Store in chat history
    const chatKey1 = `${sender}_${recipient}`;
    const chatKey2 = `${recipient}_${sender}`;
    
    if (!chatHistory[chatKey1] && !chatHistory[chatKey2]) {
      chatHistory[chatKey1] = [message];
    } else if (chatHistory[chatKey1]) {
      chatHistory[chatKey1].push(message);
    } else {
      chatHistory[chatKey2].push(message);
    }
    
    // Emit to recipient if online
    let recipientSocketId = null;
    for (const id in onlineUsers) {
      if (onlineUsers[id] === recipient) {
        recipientSocketId = id;
        break;
      }
    }
    
    if (recipientSocketId) {
      // Update status to delivered
      message.status = 'delivered';
      
      // Update in chat history
      if (chatHistory[chatKey1]) {
        chatHistory[chatKey1][chatHistory[chatKey1].length - 1].status = 'delivered';
      } else {
        chatHistory[chatKey2][chatHistory[chatKey2].length - 1].status = 'delivered';
      }
      
      // Send to recipient
      io.to(recipientSocketId).emit('receiveMessage', {
        ...message,
        conversationKey: chatKey2
      });
    }
    
    // Also send to sender for UI update
    socket.emit('messageSent', {
      ...message,
      conversationKey: chatKey1
    });
  });
  
  // Mark message as read
  socket.on('markAsRead', (data) => {
    const { sender, recipient, messageId } = data;
    
    const chatKey1 = `${sender}_${recipient}`;
    const chatKey2 = `${recipient}_${sender}`;
    
    // Update message status in history
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
    
    // Notify sender
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
  
  // Typing indicator
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
    
    // Notify recipient
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
  
  // WebRTC signaling
  socket.on('webrtc-offer', (data) => {
    const { roomId, sender, recipient, offer } = data;
    
    // Check if room exists, if not create it
    if (!callRooms[roomId]) {
      const maxParticipants = data.type === 'conference' ? 10 : (data.type === 'group' ? 5 : 2);
      callRooms[roomId] = {
        type: data.type || 'video',
        participants: [sender],
        maxParticipants: maxParticipants
      };
    }
    
    // Add sender to room if not already there
    if (!callRooms[roomId].participants.includes(sender)) {
      if (callRooms[roomId].participants.length < callRooms[roomId].maxParticipants) {
        callRooms[roomId].participants.push(sender);
      } else {
        return socket.emit('roomFull', { roomId });
      }
    }
    
    // Send offer to recipient
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
    
    // Add sender to room if not already there
    if (callRooms[roomId] && !callRooms[roomId].participants.includes(sender)) {
      if (callRooms[roomId].participants.length < callRooms[roomId].maxParticipants) {
        callRooms[roomId].participants.push(sender);
      } else {
        return socket.emit('roomFull', { roomId });
      }
    }
    
    // Send answer to recipient
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
    
    // Send ICE candidate to target user
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
        
        // Notify all participants in the room
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
              participants: [...callRooms[roomId].participants] // clone array
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
      
      // If room is empty, delete it
      if (callRooms[roomId].participants.length === 0) {
        delete callRooms[roomId];
      } else {
        // Notify remaining participants
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
              participants: [...callRooms[roomId].participants] // clone array
            });
          }
        }
      }
    }
  });
  
  // Get room info
  socket.on('get-room-info', (data) => {
    const { roomId } = data;
    
    if (callRooms[roomId]) {
      socket.emit('room-info', {
        roomId: roomId,
        type: callRooms[roomId].type,
        participants: [...callRooms[roomId].participants], // clone array
        maxParticipants: callRooms[roomId].maxParticipants
      });
    } else {
      socket.emit('room-not-found', { roomId });
    }
  });
});

// Create uploads directory if it doesn't exist
fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true }).catch(console.error);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Test signup/login with real strings (no copy-paste from password managers)');
});
