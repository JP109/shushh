// dh-signaling-server/server.js
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({ port: 4000 });
let nextId = 1;
const clients = new Map(); // id → ws

wss.on("connection", (ws) => {
  const id = nextId++;
  clients.set(id, ws);
  ws.send(JSON.stringify({ type: "welcome", id }));

  ws.on("message", (msg) => {
    let m;
    try {
      m = JSON.parse(msg);
    } catch {
      return;
    }

    console.log("M", m);

    // all messages have .to and .type
    const target = clients.get(m.to);
    if (!target) return;

    // forward everything else
    target.send(
      JSON.stringify({
        ...m,
        from: id,
      })
    );
  });

  ws.on("close", () => {
    clients.delete(id);
  });
});

console.log("Signaling server listening on ws://localhost:4000");
