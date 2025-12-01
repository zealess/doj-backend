const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { authMiddleware } = require("../middleware/auth");

const router = express.Router();

// Utilitaire pour générer un token JWT
function generateToken(user) {
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
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

    const user = new User({
      username,
      email,
      password,
      // champs structure par défaut
      sector: null,
      service: null,
      poles: [],
      habilitations: [],
      fjf: false,
    });

    await user.save();

    return res.status(201).json({
      message: "Compte créé avec succès.",
    });
  } catch (error) {
    console.error("Erreur register:", error);
    return res.status(500).json({ message: "Erreur serveur." });
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

    // identifier = email OU username
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

    const token = generateToken(user);
    const safeUser = user.toSafeObject();

    return res.json({
      message: "Connexion réussie.",
      token,
      user: safeUser,
    });
  } catch (error) {
    console.error("Erreur login:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// GET /api/auth/me  (profil courant)
// ──────────────────────────────────────────
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    const safeUser = user.toSafeObject();
    return res.json({ user: safeUser });
  } catch (error) {
    console.error("Erreur /me:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// PUT /api/auth/profile  (maj structure interne)
// ──────────────────────────────────────────
router.put("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    // Seuls ces grades peuvent modifier la structure
    const allowedRoles = [
      "Juge Fédéral",
      "Juge Fédéral Adjoint",
      "Juge Assesseur",
    ];

    const isAllowed = user.judgeGrade && allowedRoles.includes(user.judgeGrade);

    if (!isAllowed) {
      return res.status(403).json({
        message:
          "Vous n'avez pas les droits pour modifier la structure de ce profil.",
      });
    }

    const { sector, service, poles, habilitations, fjf } = req.body;

    user.sector = sector ?? null;
    user.service = service ?? null;
    user.poles = Array.isArray(poles) ? poles : [];
    user.habilitations = Array.isArray(habilitations)
      ? habilitations
      : [];
    user.fjf = !!fjf;

    await user.save();
    const safeUser = user.toSafeObject();

    return res.json({
      message: "Profil mis à jour.",
      user: safeUser,
    });
  } catch (error) {
    console.error("Erreur update profil:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = router;
