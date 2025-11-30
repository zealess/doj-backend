// routes/discord.js
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  DISCORD_ROLE_JF_ID,
  DISCORD_ROLE_JFA_ID,
  DISCORD_ROLE_JA_ID,
  JWT_SECRET,
} = process.env;

// GET /api/discord/login?token=JWT
router.get("/login", (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).send("Missing token");
  }

  // On met le JWT dans "state" pour le récupérer à la callback
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    scope: "identify",
    redirect_uri: DISCORD_REDIRECT_URI,
    state: token,
    prompt: "consent",
  });

  const url = `https://discord.com/api/oauth2/authorize?${params.toString()}`;
  return res.redirect(url);
});

// helper pour mapper les rôles -> grade
function computeJudgeGrade(roles = []) {
  if (!Array.isArray(roles)) return "Non défini";

  if (DISCORD_ROLE_JF_ID && roles.includes(DISCORD_ROLE_JF_ID)) {
    return "Juge Fédéral";
  }
  if (DISCORD_ROLE_JFA_ID && roles.includes(DISCORD_ROLE_JFA_ID)) {
    return "Juge Fédéral Adjoint";
  }
  if (DISCORD_ROLE_JA_ID && roles.includes(DISCORD_ROLE_JA_ID)) {
    return "Juge Assesseur";
  }
  return "Non défini";
}

// GET /api/discord/callback?code=...&state=JWT
router.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) {
      return res.status(400).send("Missing code or state");
    }

    // Vérifier le JWT (state) et récupérer l'id du user DOJ
    let payload;
    try {
      payload = jwt.verify(state, JWT_SECRET);
    } catch (err) {
      console.error("JWT state invalide:", err);
      return res.status(400).send("Invalid state");
    }

    const dojUserId = payload.id;

    // 1) Échanger le code OAuth Discord -> access_token
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });

    if (!tokenRes.ok) {
      console.error("Échec échange token Discord:", await tokenRes.text());
      return res.status(500).send("Discord token error");
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // 2) Infos de base utilisateur Discord
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!userRes.ok) {
      console.error("Erreur /users/@me:", await userRes.text());
      return res.status(500).send("Discord user error");
    }

    const discordUser = await userRes.json();

    // 3) Récup roles sur TON serveur via le bot
    let memberRoles = [];
    try {
      const memberRes = await fetch(
        `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${discordUser.id}`,
        {
          headers: {
            Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
          },
        }
      );

      if (memberRes.ok) {
        const memberData = await memberRes.json();
        memberRoles = memberData.roles || [];
      } else {
        console.warn(
          "Impossible de récupérer le membre Discord (peut-être pas sur le serveur ?) :",
          memberRes.status
        );
      }
    } catch (err) {
      console.error("Erreur fetch membre Discord:", err);
    }

    const judgeGrade = computeJudgeGrade(memberRoles);

    // 4) Mise à jour du User dans Mongo
    const user = await User.findById(dojUserId);
    if (!user) {
      return res.status(404).send("User DOJ not found");
    }

    user.discordId = discordUser.id;
    user.discordUsername =
      discordUser.global_name || discordUser.username || null;
    user.discordAvatar = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png?size=256`
      : null;
    user.discordLinkedAt = new Date();
    user.judgeGrade = judgeGrade;
    user.judgeGrade = judgeGrade;
    user.discordHighestRoleName = judgeGrade;
    
    await user.save();

    // 5) Redirection vers le dashboard
    // (le front lit ?discord=linked et recharge /api/auth/me)
    const redirectUrl = `https://doj-frontend-rho.vercel.app/dashboard?discord=linked`;
    return res.redirect(redirectUrl);
  } catch (err) {
    console.error("Erreur callback Discord:", err);
    return res.status(500).send("Discord callback error");
  }
});

module.exports = router;
