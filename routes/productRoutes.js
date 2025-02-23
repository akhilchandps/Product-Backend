const express = require("express");
const { createProduct, updateProduct, deleteProduct, getAllProducts,getProductById } = require("../controllers/productController");
const { authenticateUser, authorizeAdmin } = require("../middileware/authMiddileware");

const router = express.Router();

// Public Route
router.get("/", getAllProducts);

// Admin Routes
router.post("/", authenticateUser, authorizeAdmin, createProduct);
router.put("/:id", authenticateUser, authorizeAdmin, updateProduct);
router.delete("/:id", authenticateUser, authorizeAdmin, deleteProduct);
router.get("/:id", getProductById);

module.exports = router;
