const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    // ─────────────────────────
    // Auth de base
    // ─────────────────────────
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    role: {
      // rôle "technique" (user, admin, etc.) si tu veux
      type: String,
      default: "user",
    },

    // ─────────────────────────
    // Discord / serveur
    // ─────────────────────────
    discordId: { type: String },
    // pseudo Discord global
    discordUsername: { type: String },
    // pseudo sur le serveur (nickname)
    discordNickname: { type: String },
    // plus haut grade récupéré depuis le bot sur le serveur
    discordHighestRole: { type: String },
    // liste brute des rôles (si tu veux que le bot les stocke)
    discordRoles: [{ type: String }],
    discordAvatar: { type: String },
    discordLinkedAt: { type: Date },

    // ─────────────────────────
    // Structure DOJ – à attribuer manuellement
    // ─────────────────────────
    sector: { type: String },           // ex : "Section pénale", "Section civile"
    service: { type: String },          // ex : "Service instruction", "Service CI"
    poles: [{ type: String }],          // ex : ["Pôle CI", "Pôle Cour Suprême"]
    habilitations: [{ type: String }],  // ex : ["CI", "Mandats", "Fédéral"]
    fjf: { type: Boolean, default: false }, // F.J.F oui/non
  },
  { timestamps: true }
);

// Hash du mot de passe avant save
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Méthode utilitaire pour renvoyer un user sans le password
userSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.model("User", userSchema);
