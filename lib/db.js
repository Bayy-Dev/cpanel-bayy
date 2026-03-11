// lib/db.js — MongoDB connection (singleton untuk Vercel serverless)
const mongoose = require('mongoose');

let cached = global._mongoConn;
if (!cached) cached = global._mongoConn = { conn: null, promise: null };

async function connectDB() {
  if (cached.conn) return cached.conn;
  if (!cached.promise) {
    cached.promise = mongoose.connect(process.env.MONGODB_URI, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000,
    }).then(m => m);
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

// ── SCHEMAS ──────────────────────────────────────────────

const UserSchema = new mongoose.Schema({
  username:     { type: String, required: true, unique: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true },
  password:     { type: String, required: true },
  role:         { type: String, enum: ['ceo','owner','pt','reseller','admin','user'], default: 'user' },
  parentId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  firstName:    { type: String, default: '' },
  lastName:     { type: String, default: '' },
  status:       { type: String, enum: ['active','suspended'], default: 'active' },
  storageLimit: { type: Number, default: null },  // MB, null = unlimited
  storageUsed:  { type: Number, default: 0 },
  maxAccounts:  { type: Number, default: null },  // null = unlimited
  accountsUsed: { type: Number, default: 0 },
  pteroUserId:  { type: Number, default: null },
  notes:        { type: String, default: '' },
}, { timestamps: true });

const LogSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action:   { type: String },
  targetId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  detail:   { type: String, default: '' },
  ip:       { type: String, default: '' },
}, { timestamps: true });

// Prevent model redefinition in serverless hot-reload
const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Log  = mongoose.models.Log  || mongoose.model('Log',  LogSchema);

module.exports = { connectDB, User, Log };
