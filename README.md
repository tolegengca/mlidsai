# Network Intrusion Detection System (NIDS) using Machine Learning

## Overview

This project implements a Network Intrusion Detection System (NIDS) to identify malicious activities in network traffic using machine learning techniques. The goal is to classify network events as normal or malicious and detect potential anomalies that may indicate security breaches.

## Dataset

The dataset used is `ids-intrusion-csv`, which contains network traffic records labeled as normal or different types of intrusions. The dataset can be downloaded automatically using the Kagglehub library or accessed locally if Kagglehub is unavailable.

## Features

- Data loading and preprocessing, including normalization and encoding.
- Training of multiple machine learning models:
  - Random Forest classifier for intrusion detection.
  - Isolation Forest for anomaly detection.
  - PCA and KMeans clustering for dimensionality reduction and exploratory analysis.
- Performance monitoring (execution time and memory usage).
- Evaluation using classification metrics such as accuracy, precision, recall, F1-score, confusion matrix, and ROC-AUC.

## Requirements

- Python 3.7 or higher
- Libraries: numpy, pandas, scikit-learn, matplotlib, tqdm, psutil (optional), kagglehub (optional)

## Installation

```bash
pip install numpy pandas scikit-learn matplotlib tqdm psutil kagglehub
