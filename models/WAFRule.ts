import mongoose from "mongoose";

const WAFRuleSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    expression: { type: String, required: true },
    action: {
      type: String,
      enum: ["BLOCK", "ALLOW", "LOG"],
      default: "BLOCK",
    },
    priority: { type: Number, default: 0 },
    enabled: { type: Boolean, default: true },
    proxy_config_id: { type: mongoose.Schema.Types.ObjectId, ref: "ProxyConfig" },
  },
  {
    collection: "waf_rules",
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" },
  },
);

WAFRuleSchema.index({ enabled: 1, priority: -1 });
WAFRuleSchema.index({ proxy_config_id: 1, enabled: 1, priority: -1 });

export default mongoose.models.WAFRule || mongoose.model("WAFRule", WAFRuleSchema);
