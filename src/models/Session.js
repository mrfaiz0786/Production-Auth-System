import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  refreshTokenHash: {
    type: String,
    required: true,
    index: true,
  },
  userAgent: String,
  ip: String,
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 },
  },
  revoked: {
    type: Boolean,
    default: false,
  },
  revokedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

sessionSchema.index({ userId: 1, revoked: 1 });

export const Session = mongoose.model('Session', sessionSchema);