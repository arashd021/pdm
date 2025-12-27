## Dataset and ML Model Training

We provide some datasets and models trained on different attacks and applications in the `datasets` folder.
Each dataset includes ML model weights (`.pth` and `.pkl` files) and Jupyter notebooks (`.ipynb` files).

The detection datasets and model artifacts were tested with Python 3.9+. You will need the following Python packages:

pandas, numpy, torch, scikit-learn, joblib

You can install them with:

``` bash
pip install -r requirements.txt
```

Next, you can open the corresponding Jupyter notebook for each environment (testbed or AWS Fargate) and run inference on each dataset.