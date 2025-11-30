const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
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
      type: String,
      default: "user",
    },

    // --- LIAISON DISCORD ---
    discordId: { type: String },
    discordUsername: { type: String },
    discordNickname: { type: String },
    discordAvatar: { type: String },
    discordLinkedAt: { type: Date },

    // Grade le plus haut remonté par le bot / backend
    judgeGrade: { type: String },

    // --- STRUCTURE DOJ ---
    sector: { type: String },
    service: { type: String },
    poles: {
      type: [String],
      default: [],
    },
    habilitations: {
      type: [String],
      default: [],
    },
    fjf: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// ✅ Version compatible Mongoose 8 (PAS de `next`)
userSchema.pre("save", async function () {
  // Si le mot de passe n'a pas changé, on ne le re-hash pas
  if (!this.isModified("password")) return;

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Méthode de comparaison du mot de passe
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
