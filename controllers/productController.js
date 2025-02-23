const Product = require("../models/product");

exports.createProduct = async (req, res) => {
  try {
    const { name, image, price } = req.body;

    // Check if all fields are provided
    if (!name || !image || !price) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Create a new product
    const product = await Product.create({ name, image, price });
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: "Error creating product", error: error.message });
  }
};


exports.getAllProducts = async (req, res) => {
  try {
    const products = await Product.findAll();
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ message: "Error fetching products", error: error.message });
  }
};


exports.getProductById = async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    res.status(200).json(product);
  } catch (error) {
    res.status(500).json({ message: "Error fetching product", error: error.message });
  }
};

exports.updateProduct = async (req, res) => {
  try {
    const { name, image, price } = req.body;
    const product = await Product.findByPk(req.params.id);

    if (!product) return res.status(404).json({ message: "Product not found" });

    // Update product fields
    product.name = name || product.name;
    product.image = image || product.image;
    product.price = price || product.price;

    await product.save();
    res.status(200).json(product);
  } catch (error) {
    res.status(500).json({ message: "Error updating product", error: error.message });
  }
};


exports.deleteProduct = async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);

    if (!product) return res.status(404).json({ message: "Product not found" });

    await product.destroy();
    res.status(200).json({ message: "Product deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting product", error: error.message });
  }
};
