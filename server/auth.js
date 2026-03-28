// server/auth.js

import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";
import rateLimit from "express-rate-limit";
dotenv.config();

const app = express();

const FRONTEND_URL = process.env.FRONTEND_URL || "https://shushh.onrender.com";
app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});

// — Load these from .env
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !JWT_SECRET) {
  console.error("Missing SUPABASE_URL / SERVICE_KEY / JWT_SECRET in .env");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// POST /auth/signup
app.post("/auth/signup", authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: "Need email + password + name" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  // check for existing
  const { data: existing, error: fetchErr } = await supabase
    .from("users")
    .select("id")
    .eq("email", email)
    .single();

  if (fetchErr && fetchErr.code !== "PGRST116") {
    return res.status(500).json({ error: fetchErr.message });
  }
  if (existing) {
    return res.status(409).json({ error: "Email already in use" });
  }

  // hash & insert
  const password_hash = await bcrypt.hash(password, 10);
  const { data: user, error: insertErr } = await supabase
    .from("users")
    .insert({ name, email, password_hash })
    .select("id, name, email")
    .single();

  if (insertErr) {
    return res.status(500).json({ error: insertErr.message });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

app.post("/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Need email + password" });
  }

  // 1) fetch the user and hash
  const { data: user, error: fetchErr } = await supabase
    .from("users")
    .select("id, email, name, password_hash")
    .eq("email", email)
    .single();

  if (fetchErr || !user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // 2) compare password
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // 3) sign & return
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// GET /users  → returns [{ id, email, name }, …]
app.get("/users", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  try {
    jwt.verify(authHeader.slice(7), JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
  try {
    const { data, error } = await supabase
      .from("users")
      .select("id, email, name")
      .order("email", { ascending: true });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("GET /users error:", err);
    res.status(500).json({ error: err.message || "Could not fetch users" });
  }
});

// Start the server
const PORT = process.env.PORT || 3004;
app.listen(PORT, () => {
  // console.log(`🔑 Auth server listening on http://localhost:${PORT}`);
  console.log(
    `🔑 Auth server listening on https://shushh-auth.onrender.com:${PORT}`
  );
});
