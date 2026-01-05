const bcrypt = require("bcryptjs");

const users = [
  {
    id: 1,
    username: "admin",
    password: bcrypt.hashSync("admin123", 10),
    role: "admin"
  },
  {
    id: 2,
    username: "student",
    password: bcrypt.hashSync("student123", 10),
    role: "student"
  }
];

module.exports = users;