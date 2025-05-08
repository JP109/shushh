// src/components/ChatWindow.jsx
import React, { useEffect, useState, useRef } from "react";
import { g, p, modPow, randomBigInt } from "../dh";
import { aesIgeEncrypt, aesIgeDecrypt } from "../aesIge";
import { deriveAESKeyAndIV } from "../keyDerivation";
import { utils as aesUtils } from "aes-js";

export default function ChatWindow({ user, onLogout }) {
  const wsRef = useRef(null);
  const sharedRef = useRef(null);
  const serverSecretRef = useRef(null);
  const serverAuthRef = useRef(null);
  const [myId, setMyId] = useState(null);
  const [usersList, setUsersList] = useState([]);
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

  // Fetch all other users when component mounts
  useEffect(() => {
    fetch("http://localhost:3004/users")
      .then((res) => res.json())
      .then((data) => {
        const others = data.filter((u) => u.id !== user.id);
        setUsersList(others);
      })
      .catch((err) => addLog(`[USERS] fetch error: ${err.message}`));
  }, [user.id]);

  useEffect(() => {
    // on mount, inject Authorization header or token param if needed
    const ws = new WebSocket(
      `ws://localhost:4000?token=${localStorage.getItem("token")}`
    );
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("✔ connected");
      addLog("[WS] Connection opened");
    };
    ws.onerror = (ev) => addLog(`[WS] Error: ${JSON.stringify(ev)}`);
    ws.onclose = (ev) =>
      addLog(`[WS] Closed (code=${ev.code},reason=${ev.reason})`);

    // Helper to convert hex back to Uint8Array
    const hexToBytes = (hex) =>
      new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));

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
          setMyId(user.id);
          // Check for stored auth_key
          const stored = localStorage.getItem("auth_key");
          if (stored) {
            try {
              const { key, iv } = JSON.parse(stored);
              let savedAuthKey = hexToBytes(key);
              let savedAuthiv = hexToBytes(iv);
              serverAuthRef.current = { key: savedAuthKey, iv: savedAuthiv };
              addLog("[AUTH] Reusing stored auth_key");
            } catch (err) {
              addLog(`[AUTH] Failed to reuse stored key: ${err.message}`);
            }
          } else {
            // ─── DH with server ──────────────────────────────────
            const a = randomBigInt();
            serverSecretRef.current = a;
            const A = modPow(g, a, p);
            ws.send(
              JSON.stringify({
                type: "auth-dh-request",
                public: A.toString(16),
              })
            );
            addLog("[AUTH] → DH request to server");
          }
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
          const a2 = randomBigInt();
          secretRef.current = a2;
          const B2 = modPow(g, a2, p);
          const Afrom = BigInt(`0x${m.public}`);
          const S2 = modPow(Afrom, a2, p);
          const { key: sharedKey, iv: sharedIv } = await deriveAESKeyAndIV(S2);
          sharedRef.current = { key: sharedKey, iv: sharedIv, id: m.from };
          setShared({ key: sharedKey, iv: sharedIv, id: m.from });
          ws.send(
            JSON.stringify({
              type: "dh-response",
              to: m.from,
              public: B2.toString(16),
            })
          );
          addLog(`[DH] → response to ${m.from}`);
          break;
        }

        case "dh-response": {
          addLog(`[DH] ← response from ${m.from}`);
          const a3 = secretRef.current;
          const Aresp = BigInt(`0x${m.public}`);
          const S3 = modPow(Aresp, a3, p);
          const { key: sKey, iv: sIv } = await deriveAESKeyAndIV(S3);
          sharedRef.current = { key: sKey, iv: sIv, id: m.from };
          setShared({ key: sKey, iv: sIv, id: m.from });
          break;
        }

        case "message": {
          addLog(
            `[MSG] ← nested encrypted from ${m.from}: ${m.data.length} bytes`
          );
          // First decrypt outer layer with client-server auth key
          const outerCt = new Uint8Array(m.data);
          const { key: srvKey, iv: srvIv } = serverAuthRef.current;
          const innerCt = aesIgeDecrypt(outerCt, srvKey, srvIv);
          // Then decrypt inner layer with client-client shared key
          const { key: cliKey, iv: cliIv } = sharedRef.current || {};
          if (!cliKey) {
            addLog("[MSG] No shared key after outer decrypt, skipping");
            return;
          }
          const dec = aesIgeDecrypt(innerCt, cliKey, cliIv);
          const view = new DataView(dec.buffer);
          const len = view.getUint32(0, false);
          const textBytes = new Uint8Array(dec.buffer.slice(4, 4 + len));
          const text = aesUtils.utf8.fromBytes(textBytes);
          addLog(`[MSG] decrypted final: '${text}'`);
          setChat((c) => [...c, { from: m.from, text }]);
          break;
        }

        default:
          addLog(`[WS] Unknown type: ${m.type}`);
      }
    };

    return () => ws.close();
  }, []);

  const initiateDH = (receiverID) => {
    const ws = wsRef.current;
    if (!ws || !receiverID) return;
    addLog(`[UI] Initiating DH with ${receiverID}`);
    const a = randomBigInt();
    secretRef.current = a;
    const A = modPow(g, a, p);
    ws.send(
      JSON.stringify({
        type: "dh-request",
        to: Number(receiverID),
        public: A.toString(16),
      })
    );
    addLog(`[DH] → request to ${receiverID}`);
  };

  const sendMessage = () => {
    const ws = wsRef.current;
    const sharedData = sharedRef.current;
    const text = msgIn.current?.value;
    if (!ws || !sharedData || !text) return;
    addLog(`[UI] Sending: '${text}'`);

    // build plaintext payload
    const textBytes = aesUtils.utf8.toBytes(text);
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, textBytes.length, false);
    const payload = new Uint8Array(lenBuf.length + textBytes.length);
    payload.set(lenBuf, 0);
    payload.set(textBytes, 4);

    // inner encrypt: client-client shared key
    const innerCt = aesIgeEncrypt(payload, sharedData.key, sharedData.iv);
    addLog(`[MSG] inner encrypted length: ${innerCt.length}`);

    // outer encrypt: client-server auth key
    const { key: srvKey, iv: srvIv } = serverAuthRef.current;
    const outerCt = aesIgeEncrypt(innerCt, srvKey, srvIv);
    addLog(`[MSG] nested encrypted length: ${outerCt.length}`);

    ws.send(
      JSON.stringify({
        type: "message",
        to: sharedData.id,
        data: Array.from(outerCt),
      })
    );

    setChat((c) => [...c, { from: myId, text }]);
    msgIn.current.value = "";
  };

  return (
    <div className="chat-window">
      <div className="user-bar">
        <span>
          Logged in as: <b>#{user.id}</b> ({user.email})
        </span>
        <button onClick={onLogout}>Logout</button>
      </div>

      <div className="user-list">
        <strong>Start a chat:</strong>
        <ul>
          {usersList.map((u) => (
            <li key={u.id}>
              <button onClick={() => initiateDH(u.id)}>
                {u.email} (#{u.id})
              </button>
            </li>
          ))}
        </ul>
      </div>

      <h2>Peer-to-Peer DH Chat</h2>
      <div className="status">
        Status: {status} {myId && `(you are #${myId})`}
      </div>

      {/* <div className="dh-init">
        <input
          className="peer-input"
          placeholder="peer id"
          value={peerId}
          onChange={(e) => setPeerId(e.target.value)}
        />
        <button className="dh-button" onClick={initiateDH} disabled={!peerId}>
          Initiate DH
        </button>
      </div> */}

      <div className="log-container">
        <strong>Log:</strong>
        <pre className="log-output">{log.join("\n")}</pre>
      </div>

      {shared && (
        <div className="chat-container">
          <h3>Chat (with #{shared.id})</h3>
          <div className="chat-messages">
            {chat.map((m, i) => (
              <div key={i}>
                <b>{m.from === myId ? "You" : `#${m.from}`}:</b> {m.text}
              </div>
            ))}
          </div>
          <div className="message-bar">
            <input
              className="message-input"
              ref={msgIn}
              placeholder="Type message…"
            />
            <button className="send-button" onClick={sendMessage}>
              Send
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
