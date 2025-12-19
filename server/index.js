require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.CLIENT_ORIGIN, methods: ['GET','POST'] }
});

app.use(cors({ origin: process.env.CLIENT_ORIGIN }));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log('MongoDB connected');
}).catch(err => console.error('Mongo error:', err));

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: 'chat-files',
    resource_type: 'auto',
    public_id: ${Date.now()}_
  }),
});
const upload = multer({ storage });

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  name: String,
  passwordHash: String,
  role: { type: String, enum: ['owner','admin','moderator','member'], default: 'member' }
}, { timestamps: true });

const roomSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  isPrivate: { type: Boolean, default: false }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  room: { type: String, index: true },
  authorId: mongoose.Schema.Types.ObjectId,
  authorName: String,
  text: String,
  file: { url: String, type: String, name: String, size: Number },
  time: { type: Date, default: Date.now }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Room = mongoose.model('Room', roomSchema);
const Message = mongoose.model('Message', messageSchema);

function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

const appPost = app.post.bind(app);
appPost('/api/auth/signup', async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ error: 'Email already used' });
  const passwordHash = await bcrypt.hash(password, 10);
  const role = email === process.env.OWNER_EMAIL ? 'owner' : 'member';
  const user = await User.create({ email, name, passwordHash, role });
  const token = signToken(user);
  res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
});

appPost('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Wrong password' });
  const token = signToken(user);
  res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
});

app.get('/api/rooms', auth, async (req, res) => {
  const rooms = await Room.find().sort('name');
  res.json(rooms);
});

appPost('/api/rooms', auth, async (req, res) => {
  if (!['owner','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const { name, isPrivate } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Room name required' });
  const exists = await Room.findOne({ name });
  if (exists) return res.status(409).json({ error: 'Room exists' });
  const room = await Room.create({ name: name.trim(), isPrivate: !!isPrivate });
  res.json(room);
});

appPost('/api/roles/set', auth, async (req, res) => {
  const actor = req.user;
  const { targetUserId, role } = req.body;
  if (!targetUserId || !role) return res.status(400).json({ error: 'Bad request' });
  if (role === 'owner') return res.status(403).json({ error: 'Owner immutable' });
  const isOwner = actor.role === 'owner' && actor.email === process.env.OWNER_EMAIL;
  if (role === 'admin' && !isOwner) return res.status(403).json({ error: 'Only owner can make admins' });

  const target = await User.findById(targetUserId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  target.role = role;
  await target.save();
  io.emit('user:roleUpdated', { userId: String(target._id), role });
  res.json({ ok: true });
});

appPost('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const { room } = req.body;
  if (!room) return res.status(400).json({ error: 'Room required' });

  const fileType = (req.file.resource_type === 'image')
    ? 'image'
    : (req.file.resource_type === 'video') ? 'video' : 'file';

  const msg = await Message.create({
    room,
    authorId: req.user.id,
    authorName: req.user.name || req.user.email,
    text: '',
    file: {
      url: req.file.secure_url,
      type: fileType,
      name: req.file.originalname || 'file',
      size: req.file.bytes || 0
    },
    time: new Date()
  });
  io.to(room).emit('message:new', msg);
  res.json(msg);
});

const sockets = new Map();
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    sockets.set(socket.id, user);
    socket.user = user;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', async (socket) => {
  const defaultRoom = 'general';
  await Room.updateOne({ name: defaultRoom }, {}, { upsert: true });

  socket.join(defaultRoom);
  const history = await Message.find({ room: defaultRoom }).sort({ time: 1 }).limit(200);
  socket.emit('room:history', { room: defaultRoom, messages: history });
  io.to(defaultRoom).emit('room:members', await getRoomMembers(defaultRoom));

  socket.on('room:join', async ({ room }) => {
    if (!room) return;
    await Room.updateOne({ name: room }, {}, { upsert: true });
    Array.from(socket.rooms).forEach(r => { if (r !== socket.id) socket.leave(r); });
    socket.join(room);
    const history = await Message.find({ room }).sort({ time: 1 }).limit(200);
    socket.emit('room:history', { room, messages: history });
    io.to(room).emit('room:members', await getRoomMembers(room));
  });

  socket.on('message:send', async ({ room, text }) => {
    const user = socket.user;
    if (!room || !text?.trim()) return;
    const msg = await Message.create({
      room, authorId: user.id, authorName: user.name || user.email, text: text.trim(), time: new Date()
    });
    io.to(room).emit('message:new', msg);
  });

  socket.on('message:delete', async ({ room, id }) => {
    const user = socket.user;
    if (!['owner','admin','moderator'].includes(user.role)) return;
    if (!room || !id) return;
    await Message.deleteOne({ _id: id });
    io.to(room).emit('message:deleted', id);
  });

  socket.on('disconnect', () => {
    sockets.delete(socket.id);
  });
});

async function getRoomMembers(room) {
  const set = io.sockets.adapter.rooms.get(room);
  if (!set) return [];
  return Array.from(set).map(id => {
    const u = sockets.get(id);
    return u ? { id: u.id, name: u.name || u.email, role: u.role } : null;
  }).filter(Boolean);
}

app.get('/health', (_, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log('Server listening on ' + PORT));
