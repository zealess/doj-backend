const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

/**
 * Construit l’objet utilisateur renvoyé au frontend
 */
function buildUserPayload(user) {
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
    discordHighestRole: user.discordHighestRoleName || null,
    judgeGrade: user.judgeGrade || "Non défini",

    // Structure interne
    sector: user.sector || null,
    service: user.service || null,
    poles: Array.isArray(user.poles) ? user.poles : [],
    habilitations: Array.isArray(user.habilitations) ? user.habilitations : [],
    fjf: !!user.fjf,
  };
}

// ──────────────────────────────────────────
// REGISTER
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

    return res
      .status(201)
      .json({ message: "Compte créé avec succès." });
  } catch (error) {
    console.error("Erreur register:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// LOGIN
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
      user: buildUserPayload(user),
    });
  } catch (error) {
    console.error("Erreur login:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// MIDDLEWARE D’AUTH
// ──────────────────────────────────────────

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ message: "Token manquant." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    console.error("Erreur token:", err);
    return res.status(401).json({ message: "Token invalide ou expiré." });
  }
}

// ──────────────────────────────────────────
// GET /api/auth/me
// ──────────────────────────────────────────

router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res
        .status(404)
        .json({ message: "Utilisateur introuvable." });
    }

    return res.json({
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error("Erreur /me:", err);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// ──────────────────────────────────────────
// PUT /api/auth/profile  (structure & habilitations)
// ──────────────────────────────────────────

router.put("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res
        .status(404)
        .json({ message: "Utilisateur introuvable." });
    }

    // Seuls certains grades peuvent modifier
    const allowedGrades = [
      "Juge Fédéral",
      "Juge Fédéral Adjoint",
      "Juge Assesseur",
    ];

    if (!allowedGrades.includes(user.discordHighestRoleName || "")) {
      return res.status(403).json({
        message:
          "Vous n'avez pas les droits pour modifier la structure / habilitations.",
      });
    }

    const {
      sector,
      service,
      poles,
      habilitations,
      fjf,
    } = req.body;

    user.sector = sector || null;
    user.service = service || null;

    user.poles =
      Array.isArray(poles) && poles.length > 0
        ? poles
        : [];
    user.habilitations =
      Array.isArray(habilitations) && habilitations.length > 0
        ? habilitations
        : [];
    user.fjf = !!fjf;

    await user.save();

    return res.json({
      message: "Profil mis à jour.",
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error("Erreur PUT /profile:", err);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = router;
