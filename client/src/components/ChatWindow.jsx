// src/components/ChatWindow.jsx
import React, { useEffect, useState, useRef } from "react";
import { g, p, modPow, randomBigInt } from "../dh";
import { aesIgeEncrypt, aesIgeDecrypt } from "../aesIge";
import { deriveAESKeyAndIV } from "../keyDerivation";
import { utils as aesUtils } from "aes-js";

export default function ChatWindow() {
  const wsRef = useRef(null);
  const sharedRef = useRef(null);
  const serverSecretRef = useRef(null);
  const serverAuthRef = useRef(null);
  const [myId, setMyId] = useState(null);
  const [peerId, setPeerId] = useState("");
  const [status, setStatus] = useState("⏳ connecting…");
  const [shared, setShared] = useState(null);
  const secretRef = useRef();
  const [log, setLog] = useState([]);
  const msgIn = useRef();
  const [chat, setChat] = useState([]);

  const addLog = (entry) => {
    console.log(entry);
    setLog((l) => [...l, entry]);
  };

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:4000");
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("✔ connected");
      addLog("[WS] Connection opened");
    };
    ws.onerror = (ev) => addLog(`[WS] Error: ${JSON.stringify(ev)}`);
    ws.onclose = (ev) =>
      addLog(`[WS] Closed (code=${ev.code},reason=${ev.reason})`);

    ws.onmessage = async (ev) => {
      addLog(`[WS] Received raw: ${ev.data}`);
      let m;
      try {
        m = JSON.parse(ev.data);
      } catch (e) {
        addLog(`[WS] JSON parse error: ${e.message}`);
        return;
      }

      switch (m.type) {
        case "welcome":
          setMyId(m.id);
          addLog(`[WS] Assigned ID: ${m.id}`);
          // ─── DH with server ──────────────────────────────────────
          const a = randomBigInt();
          serverSecretRef.current = a;
          const A = modPow(g, a, p);
          ws.send(
            JSON.stringify({ type: "auth-dh-request", public: A.toString(16) })
          );
          addLog("[AUTH] → DH request to server");
          break;

        case "auth-dh-response":
          addLog("[AUTH] ← DH response from server");
          const aPriv = serverSecretRef.current;
          const Bpub = BigInt(`0x${m.public}`);
          const Ssec = modPow(Bpub, aPriv, p);
          const { key: authKey, iv: authIv } = await deriveAESKeyAndIV(Ssec);
          serverAuthRef.current = { key: authKey, iv: authIv };
          // store auth_key
          const bytesToHex = (bytes) =>
            Array.from(bytes)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
          localStorage.setItem(
            "auth_key",
            JSON.stringify({ key: bytesToHex(authKey), iv: bytesToHex(authIv) })
          );
          addLog("[AUTH] Stored auth_key in localStorage");
          break;

        case "dh-request": {
          addLog(`[DH] ← request from ${m.from}`);
          const a = randomBigInt();
          secretRef.current = a;
          const B = modPow(g, a, p);
          const A = BigInt(`0x${m.public}`);
          const S = modPow(A, a, p);
          const { key, iv } = await deriveAESKeyAndIV(S);
          sharedRef.current = { key, iv, id: m.from };
          setShared({ key, iv, id: m.from });
          ws.send(
            JSON.stringify({
              type: "dh-response",
              to: m.from,
              public: B.toString(16),
            })
          );
          addLog(`[DH] → response to ${m.from}`);
          break;
        }

        case "dh-response": {
          addLog(`[DH] ← response from ${m.from}`);
          const a2 = secretRef.current;
          const Aresp = BigInt(`0x${m.public}`);
          const Sresp = modPow(Aresp, a2, p);
          const { key, iv } = await deriveAESKeyAndIV(Sresp);
          sharedRef.current = { key, iv, id: m.from };
          setShared({ key, iv, id: m.from });
          break;
        }

        case "message": {
          addLog(`[MSG] ← encrypted from ${m.from}: ${m.data.length} bytes`);
          const cur = sharedRef.current;
          if (!cur) {
            addLog("[MSG] No shared key, skipping");
            return;
          }
          const data = new Uint8Array(m.data);
          const dec = aesIgeDecrypt(data, cur.key, cur.iv);
          const view = new DataView(dec.buffer);
          const len = view.getUint32(0, false);
          const textBytes = new Uint8Array(dec.buffer.slice(4, 4 + len));
          const text = aesUtils.utf8.fromBytes(textBytes);
          addLog(`[MSG] decrypted: '${text}'`);
          setChat((c) => [...c, { from: m.from, text }]);
          break;
        }

        default:
          addLog(`[WS] Unknown type: ${m.type}`);
      }
    };

    return () => ws.close();
  }, []);

  const initiateDH = () => {
    const ws = wsRef.current;
    if (!ws || !peerId) return;
    addLog(`[UI] Initiating DH with ${peerId}`);
    const a = randomBigInt();
    secretRef.current = a;
    const A = modPow(g, a, p);
    ws.send(
      JSON.stringify({
        type: "dh-request",
        to: Number(peerId),
        public: A.toString(16),
      })
    );
    addLog(`[DH] → request to ${peerId}`);
  };

  const sendMessage = () => {
    const ws = wsRef.current;
    const cur = sharedRef.current;
    const text = msgIn.current?.value;
    if (!ws || !cur || !text) return;
    addLog(`[UI] Sending: '${text}'`);
    const textBytes = aesUtils.utf8.toBytes(text);
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, textBytes.length, false);
    const payload = new Uint8Array(lenBuf.length + textBytes.length);
    payload.set(lenBuf, 0);
    payload.set(textBytes, 4);
    const ct = aesIgeEncrypt(payload, cur.key, cur.iv);
    addLog(`[MSG] encrypted length: ${ct.length}`);
    ws.send(
      JSON.stringify({ type: "message", to: cur.id, data: Array.from(ct) })
    );
    setChat((c) => [...c, { from: myId, text }]);
    msgIn.current.value = "";
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Peer-to-Peer DH Chat</h2>
      <div>
        Status: {status} {myId && `(you are #${myId})`}
      </div>

      <div style={{ margin: "1em 0" }}>
        <input
          placeholder="peer id"
          value={peerId}
          onChange={(e) => setPeerId(e.target.value)}
        />
        <button onClick={initiateDH} disabled={!peerId}>
          Initiate DH
        </button>
      </div>

      <div>
        <strong>Log:</strong>
        <pre
          style={{
            background: "#222",
            color: "#0f0",
            padding: 10,
            height: 200,
            overflowY: "auto",
          }}
        >
          {log.join("\n")}
        </pre>
      </div>

      {shared && (
        <div style={{ marginTop: 20 }}>
          <h3>Chat (with #{shared.id})</h3>
          <div
            style={{
              maxHeight: 200,
              overflowY: "auto",
              background: "#000",
              padding: 10,
            }}
          >
            {chat.map((m, i) => (
              <div key={i}>
                <b>{m.from === myId ? "You" : `#${m.from}`}:</b> {m.text}
              </div>
            ))}
          </div>
          <input ref={msgIn} placeholder="Type message…" />
          <button onClick={sendMessage}>Sesnd</button>
        </div>
      )}
    </div>
  );
}
