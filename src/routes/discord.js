const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  JWT_SECRET,
} = process.env;

// Petits helpers pour les URL OAuth
function getDiscordAuthorizeUrl(token) {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify guilds guilds.members.read",
    state: token,
  });

  return `https://discord.com/api/oauth2/authorize?${params.toString()}`;
}

// ──────────────────────────────────────────
// GET /api/discord/login
// Lance l'OAuth Discord à partir du token JWT du portail
// ──────────────────────────────────────────
router.get("/login", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).send("Token manquant.");
    }

    // Vérifier que le token JWT est valide
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      console.error("JWT invalide dans /discord/login:", err);
      return res.status(401).send("Token invalide.");
    }

    // On ne fait rien de plus ici, on redirige juste sur Discord
    const url = getDiscordAuthorizeUrl(token);
    return res.redirect(url);
  } catch (err) {
    console.error("Erreur /discord/login:", err);
    return res.status(500).send("Erreur serveur Discord login");
  }
});

// ──────────────────────────────────────────
// GET /api/discord/callback
// Callback OAuth Discord → on link le compte à l'utilisateur
// ──────────────────────────────────────────
router.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send("Code ou state manquant.");
    }

    // `state` contient le JWT du portail
    let decoded;
    try {
      decoded = jwt.verify(state, JWT_SECRET);
    } catch (err) {
      console.error("JWT invalide dans /discord/callback:", err);
      return res.status(401).send("Token invalide.");
    }

    const userId = decoded.id;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("Utilisateur introuvable.");
    }

    // 1) Échanger le code contre un access_token Discord
    const tokenResponse = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { access_token, token_type } = tokenResponse.data;
    const authHeader = `${token_type} ${access_token}`;

    // 2) Récupérer l'identité Discord de l'utilisateur
    const meResp = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: authHeader },
    });

    const discordUser = meResp.data;
    const discordUserId = discordUser.id;
    const discordUsername =
      discordUser.global_name || discordUser.username || "Inconnu";

    // 3) Si on a un BOT_TOKEN + GUILD_ID, on va chercher les infos de grade/nickname
    let nickname = null;
    let highestRole = null;

    if (DISCORD_BOT_TOKEN && DISCORD_GUILD_ID) {
      try {
        // Récupérer les infos du membre dans le serveur
        const memberResp = await axios.get(
          `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}`,
          {
            headers: {
              Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
            },
          }
        );

        const guildMember = memberResp.data;

        nickname = guildMember.nick || null;

        // Récupérer les rôles du serveur
        const rolesResp = await axios.get(
          `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/roles`,
          {
            headers: {
              Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
            },
          }
        );

        const guildRoles = rolesResp.data; // tableau de { id, name, ... }

        const matchingRoles = guildMember.roles
          .map((roleId) => guildRoles.find((r) => r.id === roleId))
          .filter(Boolean);

        const gradeOrder = [
          "Juge Fédéral",
          "Juge Fédéral Adjoint",
          "Juge Assesseur",
          "Juge",
          "Magistrat",
        ];

        for (const label of gradeOrder) {
          const found = matchingRoles.find((r) => r && r.name === label);
          if (found) {
            highestRole = label;
            break;
          }
        }
      } catch (err) {
        // 400 si l'utilisateur n'est pas dans le serveur ou autre souci
        console.error(
          "Impossible de récupérer le membre Discord (peut-être pas sur le serveur ?) :",
          err.response?.status || err.message
        );
      }
    }

    // 4) Sauvegarder sur l'utilisateur
    // ...
user.discordId = discordUser.id;
user.discordUsername = discordUser.global_name || discordUser.username;
user.discordNickname =
  member.nick || discordUser.global_name || discordUser.username;
user.discordAvatar = avatarUrl;
user.discordLinkedAt = new Date();

// 🔥 Ici : on enregistre le grade le plus haut
user.judgeGrade = highestRoleName || null;

await user.save();

    // 5) Redirection vers le dashboard avec un flag pour refresh
    const redirectUrl = `https://doj-frontend-rho.vercel.app/dashboard?discord=linked`;
    return res.redirect(redirectUrl);
  } catch (err) {
    console.error("Erreur callback Discord:", err);
    return res.status(500).send("Discord callback error");
  }
});

module.exports = router;
