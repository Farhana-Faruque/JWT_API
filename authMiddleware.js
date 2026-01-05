const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const SECRET_KEY = process.env.JWT_SECRET || "a7f9e2b1c4d8f3a6e9b2c5d8f1a4b7c0e3f6a9d2e5f8b1c4d7e0a3f6b9c2e5";

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  // Expect: Bearer <token>
  if (!authHeader) {
    return res.status(401).json({ message: "Token missing" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Invalid token format" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    req.user = decoded; // { userId, role, iat, exp }
    next();
  });
}

module.exports = authenticateToken;