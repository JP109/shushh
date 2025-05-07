// src/App.jsx
import React from "react";
import ChatWindow from "./components/ChatWindow";
import "./index.css";

export default function App() {
  return (
    <div style={{ padding: 20 }}>
      {/* TODO: Implement Login/Signup component and switch based on auth state */}
      <ChatWindow />
    </div>
  );
}
