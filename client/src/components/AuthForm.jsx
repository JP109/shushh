// src/components/AuthForm.jsx
import React, { useState } from "react";
import "./AuthForm.css";

export default function AuthForm({ onSuccess }) {
  const [mode, setMode] = useState("login"); // "login" | "signup"
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      // const url = mode === "login" ? "/auth/login" : "/auth/signup";
      const body = {
        email,
        password,
        ...(mode === "signup" && { name }),
      };
      // // Uncomment for local testing
      // const res = await fetch(`http://localhost:3004/auth/${mode}`, {
      //   method: "POST",
      //   headers: { "Content-Type": "application/json" },
      //   body: JSON.stringify(body),
      // });
      const res = await fetch(`https://shushh-auth.onrender.com/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Authentication failed");
      } else {
        onSuccess({ token: data.token, user: data.user });
      }
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="auth-container">
      <h1 className="title">Welcome to TeleChat</h1>
      <h3 className="subtitle">An e2ee messaging app based on MTProto 2.0</h3>
      <div className="auth-form">
        <h2>{mode === "login" ? "Log In" : "Sign Up"}</h2>
        <form onSubmit={submit}>
          {mode === "signup" && (
            <div>
              <input
                placeholder="Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          )}
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button type="submit">
            {mode === "login" ? "Log In" : "Sign Up"}
          </button>
        </form>
        {error && <div className="error">{error}</div>}
        <p onClick={() => setMode(mode === "login" ? "signup" : "login")}>
          {mode === "login"
            ? "Don't have an account? Sign up"
            : "Have an account? Log in"}
        </p>
      </div>
    </div>
  );
}
