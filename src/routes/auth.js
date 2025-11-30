const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authMiddleware = require("../middleware/auth");

const router = express.Router();

// POST /api/auth/register
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

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
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
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// POST /api/auth/login
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
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,

        discordLinked: !!user.discordId,
        discordUsername: user.discordUsername || null,
        discordAvatar: user.discordAvatar || null,
        discordHighestRoleName: user.discordHighestRoleName || null,

        sector: user.sector,
        service: user.service,
        poles: user.poles,
        habilitations: user.habilitations,
        fjf: user.fjf,
      },
    });
  } catch (error) {
    console.error("Erreur login:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// GET /api/auth/me
// Retourne l'utilisateur connecté à partir du token JWT
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    return res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,

        discordLinked: !!user.discordId,
        discordUsername: user.discordUsername || null,
        discordAvatar: user.discordAvatar || null,
        judgeGrade: user.judgeGrade || "Non défini",
        sector: user.sector,
        poles: user.poles,
        habilitations: user.habilitations,
        fjf: user.fjf,
        service: user.service,
      },
    });
  } catch (err) {
    console.error("Erreur /me:", err);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

// -------------------------------------------------------------------
// PUT /api/auth/profile
// Mise à jour des informations "structure" du magistrat
// (secteur, pôles, habilitations, FJF, service)
//
// Seuls les grades suivants peuvent modifier :
// - Juge Fédéral
// - Juge Fédéral Adjoint
// - Juge Assesseur
// -------------------------------------------------------------------
router.put("/profile", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id; // supposé rempli par authMiddleware
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    const ALLOWED_GRADES = [
      "Juge Fédéral",
      "Juge Fédéral Adjoint",
      "Juge Assesseur",
    ];

    // On base les droits sur le plus haut grade Discord
    if (!ALLOWED_GRADES.includes(user.discordHighestRole || "")) {
      return res.status(403).json({
        message:
          "Vous n'avez pas les droits nécessaires pour modifier les informations structurelles.",
      });
    }

    const { sector, service, poles, habilitations, fjf } = req.body;

    if (sector !== undefined) user.sector = sector;
    if (service !== undefined) user.service = service;
    if (poles !== undefined) {
      user.poles = Array.isArray(poles)
        ? poles.filter((p) => typeof p === "string" && p.trim() !== "")
        : [];
    }
    if (habilitations !== undefined) {
      user.habilitations = Array.isArray(habilitations)
        ? habilitations.filter((h) => typeof h === "string" && h.trim() !== "")
        : [];
    }
    if (fjf !== undefined) user.fjf = !!fjf;

    await user.save();

    const safeUser = user.toSafeObject();
    return res.json({ message: "Profil mis à jour.", user: safeUser });
  } catch (error) {
    console.error("Erreur update profil:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = router;
