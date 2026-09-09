# Dataset

This folder contains the network traffic dataset used for training and testing the AI model.

### Dataset Purpose
The dataset contains normal and malicious network traffic patterns.

### Local development dataset

`generate_dataset.py` creates a deterministic, labelled dataset of normal, suspicious, and malicious traffic patterns for local model development. Generate it with:

```powershell
python generate_dataset.py
```

The generated `network_traffic.csv` has packets, bytes, port, protocol, bytes-per-packet, and label columns. It is a synthetic development dataset; replace or supplement it with an approved source such as CIC-IDS2017 before production use.

### Usage
The dataset will be used to:
- Train the machine learning model
- Test threat detection
- Identify suspicious unidirectional IP traffic
- 
