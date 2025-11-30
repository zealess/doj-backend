const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL;
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * GET /api/discord/login
 * Redirige l'utilisateur vers la page d'autorisation Discord.
 * On reçoit le token JWT en query (?token=...)
 */
router.get("/login", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(401).send("Token manquant");
    }

    // On s'assure que le token est valide et on récupère l'id utilisateur
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      console.error("JWT invalide dans /api/discord/login:", e);
      return res.status(401).send("Token invalide");
    }

    if (!decoded || !decoded.id) {
      return res.status(401).send("Token invalide");
    }

    const state = token; // on utilise le JWT comme state

    const params = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      redirect_uri: DISCORD_REDIRECT_URI,
      response_type: "code",
      scope: "identify",
      state,
      prompt: "consent",
    });

    const discordUrl = `https://discord.com/oauth2/authorize?${params.toString()}`;
    return res.redirect(discordUrl);
  } catch (err) {
    console.error("Erreur /api/discord/login:", err);
    return res.status(500).send("Erreur interne");
  }
});

/**
 * GET /api/discord/callback
 * Callback OAuth de Discord : on reçoit ?code=&state=
 * On échange le code contre un access_token, on récupère le profil Discord
 * et on met à jour le User avec les infos Discord.
 */
router.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send("Paramètres manquants");
    }

    // state = token JWT qu'on avait utilisé dans /login
    let decoded;
    try {
      decoded = jwt.verify(state, JWT_SECRET);
    } catch (e) {
      console.error("JWT invalide dans /api/discord/callback:", e);
      return res.redirect(`${FRONTEND_URL}/dashboard?discord=error`);
    }

    const userId = decoded.id;
    if (!userId) {
      return res.redirect(`${FRONTEND_URL}/dashboard?discord=error`);
    }

    // 1) Échange code -> access_token
    const body = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: DISCORD_REDIRECT_URI,
    });

    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    if (!tokenResponse.ok) {
      const txt = await tokenResponse.text();
      console.error("Discord token error:", txt);
      return res.redirect(`${FRONTEND_URL}/dashboard?discord=error`);
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // 2) Récupérer le profil Discord
    const meResponse = await fetch("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!meResponse.ok) {
      const txt = await meResponse.text();
      console.error("Discord /users/@me error:", txt);
      return res.redirect(`${FRONTEND_URL}/dashboard?discord=error`);
    }

    const me = await meResponse.json();

    const discordId = me.id;
    const username =
      me.global_name ||
      `${me.username}${
        me.discriminator && me.discriminator !== "0" ? `#${me.discriminator}` : ""
      }`;

    const avatar = me.avatar
      ? `https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png?size=256`
      : null;

    // 3) Mise à jour de l'utilisateur en base
    const user = await User.findByIdAndUpdate(
      userId,
      {
        discordId,
        discordUsername: username,
        discordAvatar: avatar,
        discordLinkedAt: new Date(),
      },
      { new: true }
    );

    if (!user) {
      console.error("Utilisateur introuvable pour lier Discord:", userId);
      return res.redirect(`${FRONTEND_URL}/dashboard?discord=error`);
    }

    // Succès : on revient sur le dashboard
    return res.redirect(`${FRONTEND_URL}/dashboard?discord=linked`);
  } catch (err) {
    console.error("Erreur /api/discord/callback:", err);
    return res.redirect(`${FRONTEND_URL}/dashboard?discord=error`);
  }
});

router.post("/sync-member", async (req, res) => {
  try {
    const {
      secret,
      discordId,
      username,
      nickname,
      avatarUrl,
      roles,
    } = req.body;

    // Sécurité : secret bot
    if (!secret || secret !== process.env.DISCORD_BOT_SECRET) {
      return res.status(403).json({ message: "Accès non autorisé." });
    }

    if (!discordId) {
      return res.status(400).json({ message: "discordId manquant." });
    }

    // Fonction pour déterminer le grade le plus haut
    const computeHighestRole = (roleNames = []) => {
      // Classement par importance (du plus haut au plus bas)
      const RANKING = [
        "Juge Fédéral",
        "Juge Fédéral Adjoint",
        "Juge Assesseur",
        "Juge d'État",
        "Magistrat",
        "Greffier",
      ];

      // On cherche le premier rôle de la liste RANKING qui est présent dans roles
      for (const grade of RANKING) {
        if (roleNames.includes(grade)) return grade;
      }

      // sinon, rien de “spécial”
      return null;
    };

    const rolesArray = Array.isArray(roles) ? roles : [];
    const highest = computeHighestRole(rolesArray);

    // On cherche l'utilisateur DOJ lié à ce discordId
    const user = await User.findOne({ discordId });

    if (!user) {
      // On ne jette pas d’erreur ultra grave : le bot peut appeler la route
      // avant que le joueur ait lié son compte DOJ.
      return res.status(404).json({
        message: "Aucun utilisateur DOJ lié à ce discordId.",
      });
    }

    user.discordUsername = username || user.discordUsername;
    user.discordNickname = nickname || user.discordNickname;
    user.discordAvatar = avatarUrl || user.discordAvatar;
    user.discordRoles = rolesArray;
    if (highest) {
      user.discordHighestRole = highest;
    }

    await user.save();

    return res.json({
      message: "Profil Discord synchronisé.",
      user: user.toSafeObject ? user.toSafeObject() : user,
    });
  } catch (error) {
    console.error("Erreur /api/discord/sync-member:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = router;
