const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const JWT_SECRET = process.env.JWT_SECRET;

// Petite fonction pour calculer le grade le plus haut à partir des noms de rôles
function computeHighestRole(roleNames = []) {
  const RANKING = [
    "Juge Fédéral",
    "Juge Fédéral Adjoint",
    "Juge Assesseur",
    "Juge d'État",
    "Magistrat",
    "Greffier",
  ];

  for (const grade of RANKING) {
    if (roleNames.includes(grade)) return grade;
  }
  return null;
}

// ⚙️ Route pour démarrer l'OAuth Discord
// Frontend appelle : GET /api/discord/login?token=xxx
router.get("/login", (req, res) => {
  const { token } = req.query; // token DOJ du user déjà connecté

  if (!token) {
    return res.status(400).json({ message: "Token DOJ manquant dans la query." });
  }

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify",
    state: token, // on renvoie le token DOJ dans state
    prompt: "consent",
  });

  const url = `https://discord.com/oauth2/authorize?${params.toString()}`;
  return res.redirect(url);
});

// 🔙 Callback après validation Discord
router.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send("Code ou state manquant.");
    }

    // state = token DOJ
    let decoded;
    try {
      decoded = jwt.verify(state, JWT_SECRET);
    } catch (err) {
      console.error("JWT state invalide:", err);
      return res.status(400).send("State invalide.");
    }

    const userId = decoded.id;
    const dojUser = await User.findById(userId);
    if (!dojUser) {
      return res.status(404).send("Utilisateur DOJ introuvable.");
    }

    // 1) On échange le code contre un access_token Discord (OAuth2)
    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: code.toString(),
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });

    if (!tokenResponse.ok) {
      const txt = await tokenResponse.text();
      console.error("Erreur échange token Discord:", tokenResponse.status, txt);
      return res.status(500).send("Erreur OAuth Discord.");
    }

    const tokenJson = await tokenResponse.json();
    const accessToken = tokenJson.access_token;

    // 2) On récupère l'utilisateur Discord (id, pseudo, avatar)
    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!userResponse.ok) {
      const txt = await userResponse.text();
      console.error("Erreur /users/@me:", userResponse.status, txt);
      return res.status(500).send("Erreur utilisateur Discord.");
    }

    const discordUser = await userResponse.json();
    const discordId = discordUser.id;

    // 3) On récupère les infos MEMBRE sur TON serveur (nickname + roles)
    //    via le BOT TOKEN (et pas via l'access_token)
    let nickname = null;
    let roleNames = [];

    if (DISCORD_BOT_TOKEN && DISCORD_GUILD_ID) {
      const memberRes = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordId}`,
        {
          headers: {
            Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
          },
        }
      );

      if (memberRes.ok) {
        const member = await memberRes.json();
        nickname = member.nick || null;

        const roleIds = Array.isArray(member.roles) ? member.roles : [];

        // 👉 Ici on mappe les IDs de rôles vers des noms "RP"
        //    (À TOI de mettre les vrais IDs de ton serveur)
        const ROLE_ID_TO_NAME = {
          "1426617765623763055": "Juge Fédéral",
          "234567890123456789": "Juge Fédéral Adjoint",
          "345678901234567890": "Juge Assesseur",
        };

        roleNames = roleIds
          .map((id) => ROLE_ID_TO_NAME[id])
          .filter((x) => typeof x === "string");

      } else {
        const txt = await memberRes.text();
        console.warn(
          "Impossible de récupérer le membre sur la guilde:",
          memberRes.status,
          txt
        );
      }
    }

    const highest = computeHighestRole(roleNames);

    // 4) On enregistre dans ton user Mongo
    dojUser.discordId = discordId;
    dojUser.discordUsername = discordUser.username;
    dojUser.discordAvatar = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png?size=256`
      : null;
    dojUser.discordNickname = nickname;
    dojUser.discordRoles = roleNames;
    if (highest) {
      dojUser.discordHighestRole = highest;
    }
    dojUser.discordLinkedAt = new Date();

    await dojUser.save();

    // 5) On redirige vers le dashboard (ou profil) côté frontend
    //    Tu peux adapter l'URL, par ex: /profile
    return res.redirect("https://doj-frontend-rho.vercel.app/dashboard");
  } catch (err) {
    console.error("Erreur callback Discord:", err);
    return res.status(500).send("Erreur serveur lors du callback Discord.");
  }
});

module.exports = router;
