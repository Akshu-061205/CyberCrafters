# Backend

This folder contains the backend of the CyberCrafters project.

### Run

```powershell
npm install
npm start
```

The API listens on `http://localhost:5000` by default. Set `PORT` to use another port. Before starting it, generate and train the model once from the repository root:

```powershell
python dataset\generate_dataset.py
python ml\train.py
```

The backend invokes `ml/predict.py` for every detection. If `python` is not in PATH, set `PYTHON_BIN` to the Python executable path.

### API

- `GET /health` - service status
- `POST /predict` - analyse one traffic record
- `POST /predict/batch` - analyse up to 100 records (`{ "traffic": [...] }`)
- `GET /detections?limit=20` - recent in-memory detections
- `GET /dashboard/summary` - dashboard metrics

`POST /predict` requires `src_ip`, `dst_ip`, `packets`, and `bytes`; optional fields include `port` and `protocol`.

```json
{
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "packets": 100,
  "bytes": 5000,
  "port": 443,
  "protocol": "TCP"
}
```

Predictions come from the local Gaussian Naive Bayes model and include class probabilities and confidence. The response also includes transparent traffic-pattern reasons for dashboard display.

### Technology
- Node.js
- Express.js
