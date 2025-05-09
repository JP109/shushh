// server.mjs
import { WebSocketServer } from "ws";
import jwt from "jsonwebtoken";
import { g, p, modPow, randomBigInt } from "./dh.mjs";
import { deriveAESKeyAndIV } from "./keyDerivation.mjs";
import { aesIgeEncrypt, aesIgeDecrypt } from "./aesIge.mjs";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
dotenv.config();

// — Load these from .env
const JWT_SECRET = process.env.JWT_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !JWT_SECRET) {
  console.error("Missing SUPABASE_URL / SERVICE_KEY / JWT_SECRET in .env");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const wss = new WebSocketServer({ port: 4000 });

// Maps now keyed by permanent userId
const clients = new Map(); // userId → WebSocket
const authKeys = new Map(); // userId → { key, iv }

// Pending-messages store for offline delivery
const pendingMessages = new Map(); // userId → Array< { type, from, data } >

// helper to hex-encode a Uint8Array
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// hex→Uint8Array helper
function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((h) => parseInt(h, 16)));
}

wss.on("connection", async (ws, req) => {
  // 1️⃣ Grab token from the URL
  const url = new URL(req.url, `ws://${req.headers.host}`);
  const token = url.searchParams.get("token");
  console.log("▶ Incoming token:", token);
  if (!token) {
    ws.close(4001, "Authentication token required");
    return;
  }

  // 2️⃣ Verify & decode
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    ws.close(4002, "Invalid or expired token");
    return;
  }
  const userId = payload.userId;

  // 3️⃣ Register this socket under the real userId
  clients.set(userId, ws);

  // preload existing key/iv from DB (if any)
  const { data: userRow, error } = await supabase
    .from("users")
    .select("auth_key, auth_iv")
    .eq("id", userId)
    .single();

  if (userRow && userRow.auth_key && userRow.auth_iv) {
    const key = hexToBytes(userRow.auth_key);
    const iv = hexToBytes(userRow.auth_iv);
    authKeys.set(userId, { key, iv });
    console.log(`[AUTH] loaded persisted key for user ${userId}`);
  }

  ws.send(JSON.stringify({ type: "welcome", id: userId }));

  // Flush any queued messages for this user
  const queue = pendingMessages.get(userId);
  if (queue && queue.length) {
    queue.forEach((envelope) => {
      ws.send(JSON.stringify(envelope));
      console.log(`[OFFLINE] Delivered pending to ${userId}:`, envelope);
    });
    pendingMessages.delete(userId);
  }

  ws.on("message", async (raw) => {
    let m;
    try {
      m = JSON.parse(raw);
    } catch {
      return;
    }

    //!!!! Relay peer-logout to the other side
    if (m.type === "peer-logout") {
      const targetWs = clients.get(m.to);
      if (targetWs) {
        targetWs.send(
          JSON.stringify({
            type: "peer-logout",
            from: userId,
          })
        );
        console.log(`[WS] Relayed peer-logout from ${userId} to ${m.to}`);
      }
      return;
    }

    // ─── Handle client–server DH ──────────────────────
    if (m.type === "auth-dh-request") {
      console.log(`[AUTH] ← DH request from user ${userId}`);
      const A = BigInt(`0x${m.public}`);
      const b = randomBigInt();
      const B = modPow(g, b, p);
      const S = modPow(A, b, p);
      const { key, iv } = await deriveAESKeyAndIV(S);
      authKeys.set(userId, { key, iv });

      // 1️⃣ store on DB for persistence
      const hexKey = bytesToHex(key);
      const hexIv = bytesToHex(iv);
      await supabase
        .from("users")
        .update({ auth_key: hexKey, auth_iv: hexIv })
        .eq("id", userId);
      console.log(`[AUTH] persisted auth_key for user ${userId}`);

      ws.send(
        JSON.stringify({
          type: "auth-dh-response",
          public: B.toString(16),
        })
      );
      console.log(`[AUTH] → DH response to user ${userId}`);
      return;
    }

    if (m.type === "message") {
      const targetWs = clients.get(m.to);

      // 1) Strip outer layer (client→server auth key)
      const outerCt = Uint8Array.from(m.data);
      const { key: sendKey, iv: sendIv } = authKeys.get(userId);
      const innerCt = aesIgeDecrypt(outerCt, sendKey, sendIv);

      //!!!! 2) Ensure we have recipient’s auth_key (reload if needed)
      let recEntry = authKeys.get(m.to);
      if (!recEntry) {
        const { data: row, error } = await supabase
          .from("users")
          .select("auth_key, auth_iv")
          .eq("id", m.to)
          .single();
        if (row && row.auth_key && row.auth_iv) {
          const key = hexToBytes(row.auth_key);
          const iv = hexToBytes(row.auth_iv);
          authKeys.set(m.to, { key, iv });
          recEntry = { key, iv };
          console.log(`[AUTH] Reloaded auth_key for offline user ${m.to}`); //!!!!
        } else {
          console.error(
            `[AUTH] No persisted auth_key for offline user ${m.to}`
          ); //!!!!
        }
      }
      const { key: recKey, iv: recIv } = recEntry;

      // 3) Wrap for recipient (server→client auth key)
      const outerForRec = aesIgeEncrypt(innerCt, recKey, recIv);

      const envelope = {
        type: "message",
        from: userId,
        data: Array.from(outerForRec),
      };

      // 4) Send or queue
      if (targetWs) {
        targetWs.send(JSON.stringify(envelope));
      } else {
        const arr = pendingMessages.get(m.to) || [];
        arr.push(envelope);
        pendingMessages.set(m.to, arr);
        console.log(`[OFFLINE] Queued for ${m.to}:`, envelope);
      }

      return;
    }

    // ─── Relay DH negotiation ◆ client–client ───────
    const peerWs = clients.get(m.to);
    if (peerWs) {
      peerWs.send(JSON.stringify({ ...m, from: userId }));
    }
  });

  ws.on("close", () => {
    clients.delete(userId);
    authKeys.delete(userId);
  });
});

console.log("WebSocket server listening on ws://localhost:4000");
