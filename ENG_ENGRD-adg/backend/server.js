// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const jobRoutes = require('./routes/jobRoutes');
const applicationRoutes = require('./routes/application');
const adminRoutes = require("./routes/adminRoutes");
const authRoutes = require("./routes/authRoutes");
const twoFactorRoutes = require("./routes/twoFactorRoutes");
const newsRoutes = require("./routes/newsRoutes");
const messageRoutes = require("./routes/messageRoutes");
const homeContentRoutes = require("./routes/homeContentRoutes");
const AdminCredentials = require("./models/AdminCredentials");
const bcrypt = require("bcryptjs");

const app = express();


// Configure CORS to allow credentials and specific headers
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'http://localhost:3001'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
  optionsSuccessStatus: 200,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use('/api/jobs', jobRoutes);
app.use('/api/applications', applicationRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/auth/2fa", twoFactorRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/news", newsRoutes);
app.use("/api/messages", messageRoutes);
app.use("/api/home-content", homeContentRoutes);
app.use('/api/videos', require('./routes/videoUploadRoutes')); // Routes pour l'upload de vidéos
app.use('/api/images', require('./routes/imageUploadRoutes')); // Routes pour l'upload d'images 
// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI, {})
  .then(async () => {
    console.log('MongoDB connected');
    // Seed admin credentials from .env if not already in DB
    try {
      const username = process.env.ADMIN_USERNAME || 'admin';
      const existing = await AdminCredentials.findOne({ username });
      if (!existing) {
        const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);
        await AdminCredentials.create({ username, passwordHash: hash });
        console.log('Admin credentials seeded into MongoDB');
      }
    } catch (err) {
      console.error('Failed to seed admin credentials:', err);
    }
  })
  .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));