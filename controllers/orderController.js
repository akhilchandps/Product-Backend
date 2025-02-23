// controllers/orderController.js
const { Order } = require("../models");
const Product = require("../models/product");

exports.createOrder = async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    const userId = req.user.id; 
    const name = req.user.name;
    console.log(name);
    

    // Check if product exists
    const product = await Product.findByPk(productId);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // Calculate total price
    const totalPrice = product.price * quantity;

    // Create order
    const order = await Order.create({ userId,productId,name, quantity, totalPrice });

    res.status(201).json({ message: "Order created successfully", order });
  } catch (error) {
    res.status(500).json({ message: "Error creating order", error: error.message });
  }
};

exports.getUserOrders = async (req, res) => {
  try {
    const userId = req.user.id; // Get the user's ID from the token

    // Fetch orders of the user
    const orders = await Order.findAll({
      where: { userId },
      include: [{ model: Product, attributes: ['name', 'price'] }], // Include product details
    });

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json({ orders });
  } catch (error) {
    res.status(500).json({ message: "Error fetching orders", error: error.message });
  }
};

exports.getAllOrders = async (req, res) => {
  try {
    // Only admin can fetch all orders
    const orders = await Order.findAll();

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found" });
    }

    res.status(200).json({ orders });
  } catch (error) {
    res.status(500).json({ message: "Error fetching orders", error: error.message });
  }
};

exports.updateOrderStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByPk(req.params.id);

    if (!order) return res.status(404).json({ message: "Order not found" });

    // Update order status
    order.status = status || order.status;
    await order.save();

    res.status(200).json({ message: "Order status updated", order });
  } catch (error) {
    res.status(500).json({ message: "Error updating order", error: error.message });
  }
};
