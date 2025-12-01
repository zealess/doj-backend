// backend/src/middleware/authMiddleware.js
const jwt = require("jsonwebtoken");

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Token manquant ou invalide." });
  }

  const token = authHeader.slice(7); // supprime "Bearer "

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.id;
    req.userRole = payload.role;
    next();
  } catch (err) {
    console.error("Erreur authMiddleware:", err);
    return res.status(401).json({ message: "Token invalide." });
  }
};
