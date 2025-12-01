// backend/src/routes/auth.js
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// Fonction utilitaire : user "safe" pour le front
function buildSafeUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role,

    // Discord
    discordLinked: !!user.discordId,
    discordId: user.discordId || null,
    discordUsername: user.discordUsername || null,
    discordNickname: user.discordNickname || null,
    discordAvatar: user.discordAvatar || null,
    discordHighestRole: user.judgeGrade || null,

    // Structure interne
    sector: user.sector || null,
    service: user.service || null,
    poles: Array.isArray(user.poles) ? user.poles : [],
    habilitations: Array.isArray(user.habilitations)
      ? user.habilitations
      : [],
    fjf: !!user.fjf,
  };
}

// ──────────────────────────────────────────
// POST /api/auth/register
// ──────────────────────────────────────────
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
      return res
        .status(400)
        .json({ message: "Tous les champs sont obligatoires." });
    }

    if (password !== confirmPassword) {
      return res
        .status(400)
        .json({ message: "Les mots de passe ne correspondent pas." });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });
    if (existingUser) {
      return res.status(400).json({
        message: "Un compte avec ce pseudo ou cet email existe déjà.",
      });
    }

    const user = new User({ username, email, password });
    await user.save();

    return res.status(201).json({ message: "Compte créé avec succès." });
  } catch (error) {
    console.error("Erreur register:", error);
    return res
      .status(500)
      .json({ message: "Erreur serveur lors de la création du compte." });
  }
});

// ──────────────────────────────────────────
// POST /api/auth/login
// ──────────────────────────────────────────
router.post("/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ message: "Champs manquants." });
    }

    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });

    if (!user) {
      return res.status(400).json({ message: "Identifiants invalides." });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "Identifiants invalides." });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Connexion réussie.",
      token,
      user: buildSafeUser(user),
    });
  } catch (error) {
    console.error("Erreur login:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// GET /api/auth/me  (PROFIL COURANT)
// ──────────────────────────────────────────
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    return res.json({ user: buildSafeUser(user) });
  } catch (error) {
    console.error("Erreur /me:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// PUT /api/auth/profile (mise à jour structure)
// ──────────────────────────────────────────
router.put("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    const { sector, service, poles, habilitations, fjf } = req.body;

    if (typeof sector !== "undefined") user.sector = sector;
    if (typeof service !== "undefined") user.service = service;
    if (Array.isArray(poles)) user.poles = poles;
    if (Array.isArray(habilitations)) user.habilitations = habilitations;
    if (typeof fjf !== "undefined") user.fjf = !!fjf;

    await user.save();

    return res.json({
      message: "Profil mis à jour.",
      user: buildSafeUser(user),
    });
  } catch (error) {
    console.error("Erreur update profil:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = router;
