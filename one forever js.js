const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/oneforever', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: { type: Number, required: true },
  gender: { type: String, required: true },
  city: { type: String, required: true },
  profession: String,
  education: String,
  religion: String,
  caste: String,
  income: Number,
  height: Number,
  maritalStatus: String,
  about: String,
  interests: [String],
  photos: [String],
  membership: { type: String, default: 'free' },
  membershipExpiry: Date,
  isProfileVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

// Match Schema
const matchSchema = new mongoose.Schema({
  user1: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  user2: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  matchedAt: { type: Date, default: Date.now }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false }
});

// Payment Schema
const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  plan: String,
  razorpayOrderId: String,
  razorpayPaymentId: String,
  razorpaySignature: String,
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Match = mongoose.model('Match', matchSchema);
const Message = mongoose.model('Message', messageSchema);
const Payment = mongoose.model('Payment', paymentSchema);

// Razorpay Instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId).select('-password');
    if (!req.user) {
      return res.status(401).json({ message: 'User not found' });
    }
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Razorpay Signature Verification
const verifyPaymentSignature = (orderId, paymentId, signature) => {
  try {
    const body = orderId + "|" + paymentId;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');
    
    return expectedSignature === signature;
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
};

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, age, gender, city } = req.body;

    if (!name || !email || !password || !age || !gender || !city) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      age,
      gender,
      city
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        membership: user.membership
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        membership: user.membership
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Avatar Upload Route
app.post('/api/upload-avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const avatarUrl = `/uploads/${req.file.filename}`;
    
    const user = await User.findById(req.user._id);
    user.photos = [avatarUrl];
    await user.save();

    res.json({
      message: 'Avatar uploaded successfully',
      avatarUrl: avatarUrl
    });
  } catch (error) {
    console.error('Avatar upload error:', error);
    res.status(500).json({ message: 'Error uploading avatar', error: error.message });
  }
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user by ID
app.get('/api/user/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('-password -email');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('User fetch error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Search Profiles
app.get('/api/profiles', authenticateToken, async (req, res) => {
  try {
    const {
      ageMin,
      ageMax,
      city,
      religion,
      education,
      profession,
      page = 1,
      limit = 10
    } = req.query;

    const filter = { 
      _id: { $ne: req.user._id },
      isActive: true 
    };

    if (ageMin || ageMax) {
      filter.age = {};
      if (ageMin) filter.age.$gte = parseInt(ageMin);
      if (ageMax) filter.age.$lte = parseInt(ageMax);
    }

    if (city) filter.city = new RegExp(city, 'i');
    if (religion) filter.religion = new RegExp(religion, 'i');
    if (education) filter.education = new RegExp(education, 'i');
    if (profession) filter.profession = new RegExp(profession, 'i');

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const profiles = await User.find(filter)
      .select('-password -email')
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(filter);

    res.json({
      profiles,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Profiles search error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Matching Routes
app.post('/api/like/:userId', authenticateToken, async (req, res) => {
  try {
    const likedUserId = req.params.userId;
    const currentUserId = req.user._id;

    const likedUser = await User.findById(likedUserId);
    if (!likedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    const existingMatch = await Match.findOne({
      $or: [
        { user1: currentUserId, user2: likedUserId },
        { user1: likedUserId, user2: currentUserId }
      ]
    });

    if (existingMatch) {
      return res.status(400).json({ message: 'Already interacted with this profile' });
    }

    const match = new Match({
      user1: currentUserId,
      user2: likedUserId,
      status: 'pending'
    });

    await match.save();

    const mutualMatch = await Match.findOne({
      user1: likedUserId,
      user2: currentUserId,
      status: 'pending'
    });

    if (mutualMatch) {
      await Match.updateMany(
        {
          $or: [
            { user1: currentUserId, user2: likedUserId },
            { user1: likedUserId, user2: currentUserId }
          ]
        },
        { $set: { status: 'accepted' } }
      );

      io.to(`user_${likedUserId}`).emit('newMatch', {
        message: 'You have a new match!',
        matchId: match._id
      });

      return res.json({ message: 'It\'s a match!', isMatch: true });
    }

    res.json({ message: 'Like sent successfully', isMatch: false });
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user's matches
app.get('/api/matches', authenticateToken, async (req, res) => {
  try {
    const matches = await Match.find({
      $or: [
        { user1: req.user._id, status: 'accepted' },
        { user2: req.user._id, status: 'accepted' }
      ]
    })
    .populate('user1', 'name age city profession photos')
    .populate('user2', 'name age city profession photos')
    .sort({ matchedAt: -1 });

    const formattedMatches = matches.map(match => ({
      _id: match._id,
      user: match.user1._id.toString() === req.user._id.toString() ? match.user2 : match.user1,
      matchedAt: match.matchedAt
    }));

    res.json(formattedMatches);
  } catch (error) {
    console.error('Matches fetch error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Payment Routes
app.post('/api/create-order', authenticateToken, async (req, res) => {
  try {
    const { amount, plan } = req.body;

    if (!amount || !plan) {
      return res.status(400).json({ message: 'Amount and plan are required' });
    }

    const options = {
      amount: amount * 100,
      currency: 'INR',
      receipt: `receipt_${Date.now()}`
    };

    const order = await razorpay.orders.create(options);

    const payment = new Payment({
      user: req.user._id,
      amount,
      plan,
      razorpayOrderId: order.id,
      status: 'pending'
    });

    await payment.save();

    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency
    });
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ message: 'Payment error', error: error.message });
  }
});

// Secure Payment Verification
app.post('/api/verify-payment', authenticateToken, async (req, res) => {
  try {
    const { orderId, paymentId, signature } = req.body;

    if (!orderId || !paymentId || !signature) {
      return res.status(400).json({ message: 'Missing payment details' });
    }

    // Verify Razorpay signature
    const isSignatureValid = verifyPaymentSignature(orderId, paymentId, signature);
    if (!isSignatureValid) {
      return res.status(400).json({ message: 'Payment verification failed: Invalid signature' });
    }

    const payment = await Payment.findOne({ 
      razorpayOrderId: orderId,
      user: req.user._id
    });
    
    if (!payment) {
      return res.status(404).json({ message: 'Payment record not found' });
    }

    if (payment.status === 'completed') {
      return res.status(400).json({ message: 'Payment already processed' });
    }

    // Verify payment with Razorpay API
    try {
      const razorpayPayment = await razorpay.payments.fetch(paymentId);
      
      if (razorpayPayment.status === 'captured' && 
          razorpayPayment.order_id === orderId &&
          razorpayPayment.amount === payment.amount * 100) {
        
        payment.razorpayPaymentId = paymentId;
        payment.razorpaySignature = signature;
        payment.status = 'completed';
        await payment.save();

        const membershipExpiry = new Date();
        let months = 1;
        
        const planDurations = {
          'premium': 1, 'vip': 1, '3500': 3, '5500': 6,
          '6500': 9, '8500': 12, '10500': 18, '15000': 24
        };
        
        months = planDurations[payment.plan] || 1;
        membershipExpiry.setMonth(membershipExpiry.getMonth() + months);

        await User.findByIdAndUpdate(req.user._id, {
          membership: payment.plan.includes('premium') || payment.plan.includes('vip') ? payment.plan : 'premium',
          membershipExpiry: membershipExpiry
        });

        return res.json({ 
          message: 'Payment verified and membership upgraded successfully',
          plan: payment.plan
        });
      } else {
        payment.status = 'failed';
        await payment.save();
        return res.status(400).json({ message: 'Payment verification failed' });
      }
    } catch (razorpayError) {
      console.error('Razorpay API error:', razorpayError);
      payment.status = 'failed';
      await payment.save();
      return res.status(400).json({ message: 'Payment verification failed' });
    }

  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ message: 'Verification error', error: error.message });
  }
});

// Chat Routes
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: req.user._id },
            { receiver: req.user._id }
          ]
        }
      },
      {
        $sort: { timestamp: -1 }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ["$sender", req.user._id] },
              "$receiver",
              "$sender"
            ]
          },
          lastMessage: { $first: "$message" },
          lastTimestamp: { $first: "$timestamp" }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          'user.name': 1,
          'user.photos': 1,
          'user._id': 1,
          lastMessage: 1,
          lastTimestamp: 1
        }
      },
      {
        $sort: { lastTimestamp: -1 }
      }
    ]);

    res.json(conversations);
  } catch (error) {
    console.error('Conversations fetch error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.user._id, receiver: req.params.userId },
        { sender: req.params.userId, receiver: req.user._id }
      ]
    })
    .sort({ timestamp: 1 })
    .limit(100);

    res.json(messages);
  } catch (error) {
    console.error('Messages fetch error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Real-time Chat with Socket.io
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('joinUser', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`User ${userId} joined room`);
  });

  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, message } = data;

      const newMessage = new Message({
        sender: senderId,
        receiver: receiverId,
        message
      });

      await newMessage.save();

      const populatedMessage = await Message.findById(newMessage._id)
        .populate('sender', 'name photos');

      io.to(`user_${receiverId}`).emit('newMessage', {
        message: populatedMessage,
        senderId
      });

      socket.emit('messageSent', populatedMessage);
    } catch (error) {
      console.error('Message send error:', error);
      socket.emit('messageError', { error: 'Failed to send message' });
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});