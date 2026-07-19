import mongoose from "mongoose";

const SessionSchema = new mongoose.Schema({
  userId: String,
  expiresAt: { type: Date, required: true },
  token: { type: String, required: true, unique: true },
  createdAt: Date,
  updatedAt: Date,
  ipAddress: String,
  userAgent: String
}, { collection: "session" });

SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.models.Session || mongoose.model("Session", SessionSchema);
