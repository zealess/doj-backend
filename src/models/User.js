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

    // -------- LIAISON DISCORD --------
    discordId: { type: String },
    discordUsername: { type: String },
    discordNickname: { type: String },
    discordHighestRoleId: { type: String },
    discordHighestRoleName: { type: String },
    discordAvatar: { type: String },
    discordLinkedAt: { type: Date },

    // --- Infos récupérées depuis Discord / serveur ---
    judgeGrade: {
      type: String,
      default: "Non défini", // Juge Fédéral, Juge Fédéral Adjoint, Juge Assesseur…
    },

    // -------- CHAMPS MANUELS POUR LE PROFIL --------
    sector: { type: String, default: "Non défini" },
    service: { type: String, default: "Non défini" },

    // on passe en véritables tableaux de string
    poles: { type: [String], default: [] },
    habilitations: { type: [String], default: [] },

    fjf: { type: Boolean, default: false }, // false = non habilité FJF
  },
  { timestamps: true }
);

// Hash du mot de passe
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// ➜ objet "safe" renvoyé au front
userSchema.methods.toSafeObject = function () {
  return {
    id: this._id,
    username: this.username,
    email: this.email,
    role: this.role,

    discordLinked: !!this.discordId,
    discordUsername: this.discordUsername || null,
    discordAvatar: this.discordAvatar || null,
    judgeGrade: this.judgeGrade || "Non défini",

    sector: this.sector,
    service: this.service,
    poles: this.poles || [],
    habilitations: this.habilitations || [],
    fjf: this.fjf,
  };
};

module.exports = mongoose.model("User", userSchema);
