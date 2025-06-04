// server.js - Intentionally problematic code for review
const express = require("express");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Issues: No rate limiting, no input validation, SQL injection vulnerability
app.post("/users", (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = crypto
    .createHash("md5")
    .update(password)
    .digest("hex");

  const query = `INSERT INTO users (name, email, password) VALUES ('${name}', '${email}', '${hashedPassword}')`;
  // Simulate DB query - obvious SQL injection vulnerability
  console.log("Executing:", query);

  res.json({ success: true, user: { name, email } });
});

// Issues: Path traversal vulnerability, synchronous file operations
app.get("/files/:filename", (req, res) => {
  const filename = req.params.filename;
  const filepath = `./uploads/${filename}`;

  try {
    const data = fs.readFileSync(filepath, "utf8");
    res.send(data);
  } catch (err) {
    res.status(404).send("File not found");
  }
});

// Issues: No error handling, memory leak potential
const cache = new Map();
app.get("/cache/:key", (req, res) => {
  const key = req.params.key;

  if (!cache.has(key)) {
    // Simulate expensive operation
    const value = Math.random().toString(36).repeat(1000);
    cache.set(key, value);
  }

  res.json({ key, value: cache.get(key) });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
