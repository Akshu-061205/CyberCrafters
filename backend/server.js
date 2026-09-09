const express = require("express");
const cors = require("cors");
const path = require("path");
const { spawnSync } = require("child_process");

const app = express();
const PORT = Number(process.env.PORT) || 5000;
const MAX_HISTORY = 100;
const history = [];
const ML_PREDICTOR = path.join(__dirname, "..", "ml", "predict.py");
const PYTHON_BIN = process.env.PYTHON_BIN || "python";

app.use(cors());
app.use(express.json({ limit: "100kb" }));

function isValidIpv4(value) {
  if (typeof value !== "string") return false;
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => {
    const number = Number(part);
    return /^\d+$/.test(part) && number >= 0 && number <= 255;
  });
}

function validateTraffic(traffic) {
  const errors = [];
  if (!traffic || typeof traffic !== "object" || Array.isArray(traffic)) return ["Request body must be a JSON object."];
  if (!isValidIpv4(traffic.src_ip)) errors.push("src_ip must be a valid IPv4 address.");
  if (!isValidIpv4(traffic.dst_ip)) errors.push("dst_ip must be a valid IPv4 address.");
  for (const field of ["packets", "bytes"]) {
    if (!Number.isFinite(traffic[field]) || traffic[field] < 0) errors.push(`${field} must be a non-negative number.`);
  }
  if (traffic.port !== undefined && (!Number.isInteger(traffic.port) || traffic.port < 1 || traffic.port > 65535)) errors.push("port must be an integer between 1 and 65535.");
  if (traffic.protocol !== undefined && typeof traffic.protocol !== "string") errors.push("protocol must be a string when provided.");
  return errors;
}

function analyzeTraffic(traffic) {
  const reasons = [];
  let score = 0;
  const packets = traffic.packets;
  const bytes = traffic.bytes;
  const bytesPerPacket = packets === 0 ? 0 : bytes / packets;
  const protocol = String(traffic.protocol || "").toUpperCase();

  if (packets >= 100) { score += 35; reasons.push("High packet volume"); }
  if (packets >= 1_000) { score += 20; reasons.push("Very high packet volume"); }
  if (bytes >= 5_000) { score += 20; reasons.push("High data transfer volume"); }
  if (bytes >= 100_000) { score += 15; reasons.push("Very high data transfer volume"); }
  if (packets >= 20 && bytesPerPacket < 20) { score += 15; reasons.push("Unusually small packets"); }
  if ([22, 23, 3389, 445].includes(traffic.port)) { score += 10; reasons.push("Sensitive service port targeted"); }
  if (protocol === "ICMP" && packets >= 50) { score += 10; reasons.push("Elevated ICMP traffic"); }
  if (traffic.src_ip === traffic.dst_ip) { score += 10; reasons.push("Source and destination are identical"); }

  const model = predictWithModel(traffic);
  score = model.risk_score;
  const prediction = model.prediction;
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    prediction,
    risk_score: score,
    severity: score >= 70 ? "high" : score >= 35 ? "medium" : "low",
    reasons: reasons.length ? reasons : ["Traffic is within configured baseline thresholds"],
    model: {
      type: "gaussian_naive_bayes",
      version: model.model_version,
      confidence: model.confidence,
      probabilities: model.probabilities,
    },
    analyzed_at: new Date().toISOString(),
    traffic: { ...traffic, bytes_per_packet: Number(bytesPerPacket.toFixed(2)) },
  };
}

function predictWithModel(traffic) {
  const result = spawnSync(PYTHON_BIN, [ML_PREDICTOR], {
    input: JSON.stringify(traffic),
    encoding: "utf8",
    timeout: 5000,
  });
  if (result.error) throw new Error(`ML model could not start: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`ML model failed: ${(result.stderr || "Unknown error").trim()}`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("ML model returned an invalid response.");
  }
}

function storeDetection(result) {
  history.unshift(result);
  if (history.length > MAX_HISTORY) history.pop();
}

app.get("/", (req, res) => res.json({ message: "CyberCrafters backend is running", version: "1.1.0" }));
app.get("/health", (req, res) => res.json({ status: "ok", uptime_seconds: Math.floor(process.uptime()), timestamp: new Date().toISOString() }));

app.post("/predict", (req, res) => {
  const errors = validateTraffic(req.body);
  if (errors.length) return res.status(400).json({ error: "Invalid traffic payload", details: errors });
  const result = analyzeTraffic(req.body);
  storeDetection(result);
  res.json({ ...result, message: "Traffic analyzed successfully" });
});

app.post("/predict/batch", (req, res) => {
  if (!Array.isArray(req.body?.traffic) || req.body.traffic.length === 0) return res.status(400).json({ error: "traffic must be a non-empty array." });
  if (req.body.traffic.length > 100) return res.status(400).json({ error: "A batch can contain at most 100 records." });
  const invalid = req.body.traffic.map(validateTraffic).find((errors) => errors.length);
  if (invalid) return res.status(400).json({ error: "Invalid traffic payload", details: invalid });
  const results = req.body.traffic.map(analyzeTraffic);
  results.forEach(storeDetection);
  res.json({ total: results.length, malicious: results.filter((item) => item.prediction === "Malicious").length, results });
});

app.get("/detections", (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), MAX_HISTORY);
  res.json({ total: history.length, detections: history.slice(0, limit) });
});

app.get("/dashboard/summary", (req, res) => {
  const counts = history.reduce((total, item) => { total[item.prediction] += 1; return total; }, { Normal: 0, Suspicious: 0, Malicious: 0 });
  const averageRisk = history.length ? Math.round(history.reduce((sum, item) => sum + item.risk_score, 0) / history.length) : 0;
  res.json({ total_analyzed: history.length, average_risk_score: averageRisk, detections: counts, recent: history.slice(0, 5) });
});

app.use((req, res) => res.status(404).json({ error: "Route not found" }));
app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && error.status === 400 && "body" in error) return res.status(400).json({ error: "Malformed JSON request body" });
  console.error(error);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => console.log(`CyberCrafters backend running on port ${PORT}`));
