// server.mjs
import { WebSocketServer } from "ws";
import jwt from "jsonwebtoken";
import { g, p, modPow, randomBigInt } from "./dh.mjs";
import { deriveAESKeyAndIV } from "./keyDerivation.mjs";
import { aesIgeEncrypt, aesIgeDecrypt } from "./aesIge.mjs";
import dotenv from "dotenv";
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

const wss = new WebSocketServer({ port: 4000 });

// Maps now keyed by permanent userId
const clients = new Map(); // userId → WebSocket
const authKeys = new Map(); // userId → { key, iv }

wss.on("connection", (ws, req) => {
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
  const userId = payload.userId; // <-- your signup flow must put `id` in the JWT

  // 3️⃣ Register this socket under the real userId
  clients.set(userId, ws);
  ws.send(JSON.stringify({ type: "welcome", id: userId }));

  ws.on("message", async (raw) => {
    let m;
    try {
      m = JSON.parse(raw);
    } catch {
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

      ws.send(
        JSON.stringify({
          type: "auth-dh-response",
          public: B.toString(16),
        })
      );
      console.log(`[AUTH] → DH response to user ${userId}`);
      return;
    }

    // ─── Handle nested encrypted messages ────────────
    if (m.type === "message") {
      const targetWs = clients.get(m.to);
      if (!targetWs) return; // unknown recipient

      // 1) Strip outer layer (client→server auth key)
      const outerCt = Uint8Array.from(m.data);
      const { key: sendKey, iv: sendIv } = authKeys.get(userId);
      const innerCt = aesIgeDecrypt(outerCt, sendKey, sendIv);

      // 2) Wrap for recipient (server→client auth key)
      const { key: recKey, iv: recIv } = authKeys.get(m.to);
      const outerForRec = aesIgeEncrypt(innerCt, recKey, recIv);

      // 3) Forward
      targetWs.send(
        JSON.stringify({
          type: "message",
          from: userId,
          data: Array.from(outerForRec),
        })
      );
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
