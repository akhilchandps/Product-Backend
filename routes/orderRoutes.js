// routes/orderRoutes.js
const express = require("express");
const { createOrder, getUserOrders, getAllOrders, updateOrderStatus } = require("../controllers/orderController");
const { authenticateUser, authorizeAdmin } = require("../middileware/authMiddileware");

const router = express.Router();

// User Routes
router.post("/", authenticateUser, createOrder); // User creates order
router.get("/", authenticateUser, getUserOrders); // Get user orders

// Admin Routes
router.get("/all", authenticateUser, authorizeAdmin, getAllOrders); // Get all orders (admin only)
router.put("/:id", authenticateUser, authorizeAdmin, updateOrderStatus); // Admin updates order status

module.exports = router;
