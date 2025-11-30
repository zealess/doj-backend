require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");

const authRoutes = require("./routes/auth");
const discordRoutes = require("./routes/discord");

const app = express();

// ──────────────────────────────────────────
// CORS TRÈS SIMPLE (ACLO: * POUR TOUT)
// ──────────────────────────────────────────
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // <- autorise tout
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204); // préflight OK, pas besoin d'aller plus loin
  }

  next();
});

// ──────────────────────────────────────────
// MIDDLEWARE JSON
// ──────────────────────────────────────────
app.use(express.json());

// ──────────────────────────────────────────
// ROUTES
// ──────────────────────────────────────────
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.json({ message: "Backend DOJ OK" });
});

app.use("/api/discord", discordRoutes);

// ──────────────────────────────────────────
// MONGO + LANCEMENT SERVEUR
// ──────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ Connecté à Mongo Atlas");
    const port = process.env.PORT || 5000;
    app.listen(port, () => console.log(`✅ Backend lancé sur le port ${port}`));
  })
  .catch((err) => {
    console.error("❌ Erreur de connexion Mongo:", err);
    process.exit(1);
  });
