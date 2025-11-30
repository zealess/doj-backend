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
    discordNickname:   { type: String },
    discordHighestRoleId: { type: String },
    discordHighestRoleName: { type: String },
    discordAvatar: { type: String },
    discordLinkedAt: { type: Date },

     // --- Infos récupérées depuis Discord / serveur ---
    judgeGrade: {
      type: String,
      default: "Non défini", // Juge Fédéral, Juge Fédéral Adjoint, Juge Assesseur…
    },

    // grade récupéré via Discord (rôle le plus haut)
    

    // -------- CHAMPS MANUELS POUR LE PROFIL --------
    sector: { type: String, default: "Non défini" },
    service: { type: String, default: "Non défini" },
    poles: { type: String, default: "Aucun pôle renseigné" },
    habilitations: { type: String, default: "Aucune habilitation renseignée" },
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

module.exports = mongoose.model("User", userSchema);
