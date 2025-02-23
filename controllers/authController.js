const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User } = require("../models");
require("dotenv").config();

// User Registration
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) return res.status(400).json({ message: "Email already registered" });
    let role = ''

         const result = await User.findAll();

         if(result.length >0){
               role = 'User'
         }else{
            role = 'Admin'
         }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, password: hashedPassword ,role});

    res.status(201).json({ message: "User registered successfully", user: newUser });
  } catch (error) {
    res.status(500).json({ message: "Error registering user", error });
  }
};

// User Login
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Generate Token
    const token = jwt.sign(
      { id: user.id, userrole: user.role, name:user.name },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    console.log(token);

    // Set HttpOnly Cookie
    res.cookie("AuthToken", token, {
      httpOnly: true
    });

    // Send JSON Response
    res.json({ message: "Login successful", token, user });

  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
};
// User Logout
exports.logout = async (req, res) => {
  try {
    res.clearCookie("AuthToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    
    res.json({ message: "Logout successful" });
  } catch (error) {
    res.status(500).json({ message: "Error logging out", error });
  }
};

// Get all users with the role 'User' only
exports.getAllUsers = async (req, res) => {
  try {
    // Fetch users where the role is 'User'
    const users = await User.findAll({
      where: {
        role: 'User',
      },
      attributes: ['id', 'name', 'email', 'role'], // Specify which fields to return
    });

    if (users.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }

    res.status(200).json({ users });
  } catch (error) {
    res.status(500).json({ message: "Error fetching users", error: error.message });
  }
};