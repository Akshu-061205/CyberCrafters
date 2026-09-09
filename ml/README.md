# Machine Learning

This folder contains the machine learning model for detecting cyber threats in unidirectional IP traffic.

The current model is a dependency-free Gaussian Naive Bayes classifier. It accepts packets, bytes, port, and protocol and classifies traffic as `Normal`, `Suspicious`, or `Malicious`.

```powershell
python ..\dataset\generate_dataset.py
python train.py
```

This generates `models/traffic_model.json`. Test one record through the command line:

```powershell
'{"packets":100,"bytes":5000,"port":443,"protocol":"TCP"}' | python predict.py
```
