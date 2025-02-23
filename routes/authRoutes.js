const express = require("express");
const { register, login ,logout,getAllUsers} = require("../controllers/authController");
const { authenticateUser, authorizeAdmin } = require("../middileware/authMiddileware");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout); // <-- Added Logout Route
router.get("/users", authenticateUser, authorizeAdmin, getAllUsers); // <-- This route fetches all users with the role "User"

module.exports = router;
