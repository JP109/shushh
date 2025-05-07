// server.mjs
import { WebSocketServer } from "ws";
import { g, p, modPow, randomBigInt } from "./dh.mjs";
import { deriveAESKeyAndIV } from "./keyDerivation.mjs";
import { aesIgeEncrypt, aesIgeDecrypt } from "./aesIge.mjs";

const wss = new WebSocketServer({ port: 4000 });
let nextId = 1;
const clients = new Map(); // clientId → ws
const authKeys = new Map(); // clientId → { key, iv }

wss.on("connection", (ws) => {
  const id = nextId++;
  clients.set(id, ws);
  ws.send(JSON.stringify({ type: "welcome", id }));

  ws.on("message", async (msg) => {
    let m;
    try {
      m = JSON.parse(msg);
    } catch {
      return;
    }

    // ─── Handle DH handshake with client ─────────────────────
    if (m.type === "auth-dh-request") {
      console.log(`[AUTH] ← DH request from client ${id}`);
      const A = BigInt(`0x${m.public}`);
      const b = randomBigInt();
      const B = modPow(g, b, p);
      const S = modPow(A, b, p);
      const { key, iv } = await deriveAESKeyAndIV(S);
      authKeys.set(id, { key, iv });
      console.log("auth_keys", authKeys);
      ws.send(
        JSON.stringify({ type: "auth-dh-response", public: B.toString(16) })
      );
      console.log(`[AUTH] → DH response to client ${id}`);
      return;
    }

    // ─── Handle nested encrypted messages ───────────────────
    if (m.type === "message") {
      const target = clients.get(m.to);
      if (!target) return;

      // Decrypt outer layer with sender's auth key
      const outerBytes = Uint8Array.from(m.data);
      const { key: senderKey, iv: senderIv } = authKeys.get(id);
      const innerBytes = aesIgeDecrypt(outerBytes, senderKey, senderIv);

      // Encrypt inner for recipient with their auth key
      const { key: recKey, iv: recIv } = authKeys.get(m.to);
      const outerForRec = aesIgeEncrypt(innerBytes, recKey, recIv);

      // Forward to recipient
      target.send(
        JSON.stringify({
          type: "message",
          from: id,
          data: Array.from(outerForRec),
        })
      );
      return;
    }

    // ─── Forward client-client DH negotiation messages ─────
    const target = clients.get(m.to);
    if (!target) return;
    target.send(JSON.stringify({ ...m, from: id }));
  });

  ws.on("close", () => {
    clients.delete(id);
    authKeys.delete(id);
  });
});

console.log("Signaling server listening on ws://localhost:4000");
