const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const users = require("./user");
const authenticateToken = require("./authMiddleware");

dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "MY_SUPER_SECRET_KEY";
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const isPasswordValid = bcrypt.compareSync(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { userId: user.id, role: user.role },
    SECRET_KEY,
    { expiresIn: EXPIRES_IN }
  );

  res.json({ message: "Login successful", token });
});

app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Profile accessed successfully",
    user: req.user
  });
});

app.get("/admin", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied: Admins only" });
  }

  res.json({ message: "Welcome Admin!" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});