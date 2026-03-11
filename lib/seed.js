// lib/seed.js — Jalankan sekali untuk buat akun CEO default
// Usage: node lib/seed.js
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { connectDB, User } = require('./db');

async function seed() {
  await connectDB();
  const exists = await User.findOne({ role: 'ceo' });
  if (exists) { console.log('CEO sudah ada:', exists.username); process.exit(0); }

  const hash = await bcrypt.hash('password', 10);
  await User.create({
    username: 'ceo',
    email: 'ceo@pterobot.local',
    password: hash,
    role: 'ceo',
    firstName: 'CEO',
    lastName: 'Admin',
  });
  console.log('✅ Akun CEO dibuat! Login: ceo / password');
  console.log('⚠️  Segera ganti password setelah login pertama!');
  process.exit(0);
}

seed().catch(e => { console.error(e); process.exit(1); });
