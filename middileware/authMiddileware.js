const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.authenticateUser = (req, res, next) => {
  const token = req.cookies && req.cookies.AuthToken;
  
  if (!token) {
    return res.status(401).json({ message: "Access Denied. No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decoded);
    
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid Token", error: err.message });
  }
};

exports.authorizeAdmin = (req, res, next) => {

  if (!req.user || req.user.userrole !== "Admin") {
    return res.status(403).json({ message: "Access Denied. Admins only" });
  }
  next();
};
