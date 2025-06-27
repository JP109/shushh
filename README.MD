## Overview

This project is a full-stack, end-to-end encrypted chat application inspired by Telegram’s security design. It features:

- **User Authentication** via JWT (login/signup)
- **Client–Server DH Handshake** for establishing a long-lived \`auth_key\`
- **Persistent Sessions**: \`auth_key\` stored in localStorage and database for fast reconnects
- **Client–Client DH Handshake** for secret chat sessions
- **Nested Encryption**: AES-IGE inner layer (peer key) and outer layer (auth key)
- **Accept/Decline** modal for incoming chat requests
- **Offline Message Queueing**: server-side storage & delivery on reconnect
- **Session Persistence**: secret chat keys survive page reloads
- **User Identity**: displays user names and IDs
- **Logout/Cleanup**: clears sensitive keys on logout and notifies peers

**Setup server and clients**

- **Terminal 1** (WebSocket server):

  ```bash
  cd server
  npm install
  node server.mjs
  ```

- **Terminal 2** (Auth server):

  ```bash
  cd server
  npm install
  node auth.js
  ```

- **Terminal 3** (Client 1):

  ```bash
  cd client
  npm install
  npm run dev -- --port 3000
  ```

  Open in browser: http://localhost:3000/

- **Terminal 4** (Client 2):
  ```bash
  cd client
  npm install
  npm run dev -- --port 3001
  ```
  Open in a different browser/profile!!!: http://localhost:3001/

## Usage

- **Signup** with name, email, and password, if not signed up already. Signup in both clients/browser windows.
- After you signup on the 2nd client, you might not see the 2nd user on 1st client. Just reload both clients (Shift + R in both browsers) to ensure both clients get updated user lists from the database.
- **Click** on a user from the list to initiate a secret chat.
- **Accept/Decline** on the recipient side.
- **Chat** securely with nested encryption.
- **Reload** pages; sessions and chat windows will persist.
- To test for the case where the recipient is offline. Just close the recipient client's window (either of the 2). For example you closed http://localhost:3000/ tab. Then send a message from http://localhost:3001/ tab, wait for a second, then reopen the closed tab (http://localhost:3000/). You will see that even though http://localhost:3000/ was closed when http://localhost:3001/ sent a message, it still received it after it reconnected with the server. (You can see the stored encrypted message on server logs in the terminal running the server).
- **Logout** to clear all stored keys and reset state. Logging out on even one client will close the secret chat session in both clients, as the secret chat key will be wiped from persitent storage on both clients.
- **Logging**. To see logs on client, see the console tab in developer tools (right click on the browser window then click on "Inspect", then click on console). Logs on client are also printed on the screen in the dark blue log window for your convinience. To see logs on server, just look at the terminal that is running the server.
- The database is hosted on supabase, and a screenshot of how the user table schema looks like is in my report.
