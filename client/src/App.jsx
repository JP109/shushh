// src/App.jsx
import React, { useState, useEffect } from "react";
import ChatWindow from "./components/ChatWindow";
import AuthForm from "./components/AuthForm";

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("token"));
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("user");
    return raw ? JSON.parse(raw) : null;
  });

  const handleAuthSuccess = ({ token, user }) => {
    localStorage.setItem("token", token);
    localStorage.setItem("user", JSON.stringify(user));
    setToken(token);
    setUser(user);
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setToken(null);
    setUser(null);
    window.location.reload();
  };

  return (
    <div>
      {!token ? (
        <AuthForm onSuccess={handleAuthSuccess} />
      ) : (
        <ChatWindow user={user} onLogout={handleLogout} />
      )}
    </div>
  );
}
