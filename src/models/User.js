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

    // --- Discord ---
    discordId: { type: String },
    discordUsername: { type: String },
    discordNickname: { type: String },
    discordAvatar: { type: String },
    discordLinkedAt: { type: Date },

    // Grade côté serveur Discord (récupéré par le bot)
    judgeGrade: { type: String },

    // --- Structure interne DOJ ---
    sector: { type: String, default: null },
    service: { type: String, default: null },
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

// Hash du mot de passe avant save
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare un mot de passe
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Normalisation de l'objet envoyé au frontend
userSchema.methods.toSafeObject = function () {
  const obj = this.toObject({ versionKey: false });

  return {
    id: this._id.toString(),
    username: obj.username,
    email: obj.email,
    role: obj.role,

    // Discord
    discordLinked: !!obj.discordId,
    discordId: obj.discordId || null,
    discordUsername: obj.discordUsername || null,
    discordNickname: obj.discordNickname || null,
    discordAvatar: obj.discordAvatar || null,
    judgeGrade: obj.judgeGrade || null,

    // Structure
    sector: obj.sector || null,
    service: obj.service || null,
    poles: Array.isArray(obj.poles) ? obj.poles : [],
    habilitations: Array.isArray(obj.habilitations) ? obj.habilitations : [],
    fjf: !!obj.fjf,
  };
};

module.exports = mongoose.model("User", userSchema);
