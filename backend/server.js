const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    message: "CyberCrafters Backend is running"
  });
});

app.post("/predict", (req, res) => {
  const traffic = req.body;

  res.json({
    prediction: "Suspicious",
    risk_score: 75,
    message: "Traffic received successfully",
    traffic: traffic
  });
});

const PORT = 5000;

app.listen(PORT, () => {
  console.log(`CyberCrafters backend running on port ${PORT}`);
});
