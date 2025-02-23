const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const authRoutes = require("./routes/authRoutes");
const cookieParser = require("cookie-parser");
const db = require("./models");
const productRoutes = require("./routes/productRoutes");
const orderRoutes = require("./routes/orderRoutes");

require("dotenv").config();

const app = express();

// Middleware
app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
}));
app.use(bodyParser.json());
app.use(cookieParser());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/products", productRoutes);
app.use("/api/orders", orderRoutes);

// Database Sync
db.sequelize.sync()
  .then(() => console.log("Database synced successfully"))
  .catch(err => console.log("Database sync error:", err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
