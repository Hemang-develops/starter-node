const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Allow CORS from all origins or specify yours explicitly
app.use(
  cors({
    origin: "*", // or ['https://c9s2vq-8080.csb.app'] if you want to restrict
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// ✅ Must handle preflight OPTIONS
app.options("*", cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("static"));

// In-memory user storage (replace with database in production)
// const users = [];
const db = require("./db");

// JWT Secret from environment variable
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// Routes

// Serve main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "pages", "index.html"));
});

// Register endpoint
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, code } = req.body;

    // Validation
    if (!username || !email || !password || !code) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }

    if (code.length < 6 && code !== "270319") {
      return res
        .status(400)
        .json({ error: "Incorrect Code.Contact admin for the code" });
    }

    // Check if user already exists
    const existingUser = db
      .prepare("SELECT * FROM users WHERE email = ? OR username = ?")
      .get(email, username);

    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert user into DB
    const result = db
      .prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
      .run(username, email, hashedPassword);

    const user = {
      id: result.lastInsertRowid,
      username,
      email,
    };

    res.status(201).json({
      message: "User registered successfully",
      user,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login endpoint
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Find user
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Protected route example
app.get("/api/profile", authenticateToken, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
    },
  });
});

// Logout endpoint (client-side token removal)
app.post("/api/logout", authenticateToken, (req, res) => {
  res.json({ message: "Logout successful" });
});

// Get all users (protected route)
app.get("/api/users", authenticateToken, (req, res) => {
  const users = db
    .prepare("SELECT id, username, email, createdAt FROM users")
    .all();
  const userList = users.map((user) => ({
    id: user.id,
    username: user.username,
    email: user.email,
    createdAt: user.createdAt,
  }));

  res.json({ users: userList });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access your app at http://localhost:${PORT}`);
});

module.exports = app;
