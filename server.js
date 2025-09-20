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
app.use(express.urlencoded({ extended: true })); // <-- ADDED: for form-encoded bodies

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/chat.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'chat.html'));
});

// Helper: Hash password — NOW TRIMS WHITESPACE
function hashPassword(password) {
  if (typeof password !== 'string') {
    throw new Error('Password must be a string');
  }
  return crypto.createHash('sha256').update(password.trim()).digest('hex'); // <-- TRIM!
}

// Signup route — ENHANCED
app.post('/api/signup', (req, res) => { // <-- REMOVED async, not needed
  // Handle both JSON and form-urlencoded
  let { username, password, name } = req.body;

  // Debug log raw input
  console.log('Raw signup input:', { username, password, name });

  // Sanitize input
  username = (username || '').toString().trim();
  password = (password || '').toString().trim();
  name = (name || '').toString().trim();

  // Validate input
  if (!username || !password || !name) {
    console.log('❌ Signup failed: Missing fields', { username, password, name });
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if user exists
  if (users[username]) {
    console.log('❌ Signup failed: User exists', username);
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

    console.log('✅ User created:', username);
    console.log('   Stored hash:', hashedPassword);
    res.json({ success: true, message: 'User created successfully' });
  } catch (err) {
    console.error('❌ Signup error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login route — ENHANCED
app.post('/api/login', (req, res) => { // <-- REMOVED async
  // Handle both JSON and form-urlencoded
  let { username, password } = req.body;

  // Debug log raw input
  console.log('Raw login input:', { username, password });

  // Sanitize input
  username = (username || '').toString().trim();
  password = (password || '').toString().trim();

  // Validate input
  if (!username || !password) {
    console.log('❌ Login failed: Missing username or password', { username, password });
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users[username];
  if (!user) {
    console.log('❌ Login failed: User not found', username);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  try {
    // Hash the input password
    const hashedInputPassword = hashPassword(password);

    // Compare with stored hash
    if (user.password !== hashedInputPassword) {
      console.log('❌ Login failed: Password mismatch for user', username);
      console.log('   Input password (trimmed):', password);
      console.log('   Input hash:', hashedInputPassword);
      console.log('   Stored hash:', user.password);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Update last seen
    user.lastSeen = Date.now();

    console.log('✅ Login successful:', username);
    res.json({ 
      success: true, 
      user: { 
        username: username, 
        name: user.name, 
        avatar: user.avatar 
      } 
    });
  } catch (err) {
    console.error('❌ Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ... REST OF YOUR CODE REMAINS UNCHANGED ...
// (Search, Online Users, Chat History, Upload, Socket.IO handlers — no issues there)

// Create uploads directory if it doesn't exist
fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true }).catch(console.error);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('📝 Tip: Type passwords manually. Avoid copy-paste.');
  console.log('🔐 Hashing uses SHA-256 with whitespace trimming.');
});
