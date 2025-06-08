"""
Multi‑label Model Evaluation Suite – Loguru × Click
===================================================

Cross‑validate the 13 classifier models you listed on multi‑label data.
Logs via Loguru; CLI via Click.

Usage:
```bash
python eval_multilabel_cv_improved.py \
    --data feats.joblib \
    --splits 5 \
    --output results.csv \
    --models lr_clf rfc_clf
```
The output (CSV/JSON) contains mean ± std for subset accuracy, Hamming loss,
F1/precision/recall (macro & micro), and ROC‑AUC (when available).
Author: ChatGPT – 08 Jun 2025
"""
from __future__ import annotations

import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from loguru import logger
import click

from sklearn.base import clone
from sklearn.model_selection import KFold
from sklearn.metrics import (
    accuracy_score,
    hamming_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
)
from xgboost import XGBClassifier

try:
    import joblib
except ModuleNotFoundError:
    raise ModuleNotFoundError("Install `joblib` to load .joblib files.")

# Optional stratified CV for multi-label
try:
    from iterstrat.ml_stratifiers import MultilabelStratifiedKFold as _MSKF
    def _get_cv(n_splits: int):
        logger.debug("Using MultilabelStratifiedKFold.")
        return _MSKF(n_splits=n_splits, shuffle=True, random_state=42)
except ImportError:
    warnings.warn(
        "Package 'iterative-stratification' not found – falling back to KFold.",
        ImportWarning,
    )
    def _get_cv(n_splits: int):
        return KFold(n_splits=n_splits, shuffle=True, random_state=42)

# Logger configuration
logger.remove()
logger.add(sys.stderr, level="INFO", colorize=True, format="<level>{message}</level>")
logger.add("eval_multilabel.log", rotation="100 KB", level="DEBUG",
           format="{time} | {level} | {message}")

# Base models as provided
MODEL_REGISTRY: Dict[str, Any] = {
    "lr_clf": LogisticRegression(class_weight="balanced", solver="saga", max_iter=1000,
                                 n_jobs=-1, random_state=42),
    "svm_sigmoid_clf": SVC(class_weight="balanced", probability=True,
                            kernel="sigmoid", random_state=42),
    "svm_rbf_clf": SVC(class_weight="balanced", probability=True,
                        kernel="rbf", random_state=42),
    "knn3_clf": KNeighborsClassifier(n_neighbors=3),
    "knn5_clf": KNeighborsClassifier(n_neighbors=5),
    "knn7_clf": KNeighborsClassifier(n_neighbors=7),
    "gnb_clf": GaussianNB(),
    "dt_clf": DecisionTreeClassifier(class_weight="balanced", random_state=42),
    "rfc_clf": RandomForestClassifier(class_weight="balanced", n_estimators=300,
                                       n_jobs=-1, random_state=42),
    "etc_clf": ExtraTreesClassifier(class_weight="balanced", n_estimators=300,
                                     n_jobs=-1, random_state=42),
    "gbc_clf": GradientBoostingClassifier(random_state=42),
    "hgb_clf": HistGradientBoostingClassifier(class_weight="balanced", random_state=42),
    "xgb_clf": XGBClassifier(learning_rate=0.1, objective="binary:logistic",
                               eval_metric="logloss", use_label_encoder=False,
                               n_estimators=300, n_jobs=-1, random_state=42),
}

# Metric computation for each fold
def _fold_metrics(y_true: np.ndarray,
                  y_pred: np.ndarray,
                  y_proba: np.ndarray | None) -> Dict[str, float]:
    m: Dict[str, float] = {
        "subset_acc": accuracy_score(y_true, y_pred),
        "hamming_loss": hamming_loss(y_true, y_pred),
        "f1_micro": f1_score(y_true, y_pred, average="micro", zero_division=0),
        "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "prec_micro": precision_score(y_true, y_pred, average="micro", zero_division=0),
        "rec_micro": recall_score(y_true, y_pred, average="micro", zero_division=0),
    }
    if y_proba is not None:
        try:
            m["auc_macro"] = roc_auc_score(y_true, y_proba, average="macro")
            m["auc_micro"] = roc_auc_score(y_true, y_proba, average="micro")
        except ValueError:
            m["auc_macro"] = np.nan
            m["auc_micro"] = np.nan
    return m

# Evaluate one model across CV
def evaluate_model(name: str,
                   base_model: Any,
                   X: np.ndarray,
                   Y: np.ndarray,
                   n_splits: int = 5) -> pd.Series:
    logger.info(f"\n[blue]▶ Evaluating {name} ({n_splits}-fold)...[/]")
    cv = _get_cv(n_splits)
    fold_scores: List[Dict[str, float]] = []

    for fold, (train_idx, val_idx) in enumerate(cv.split(X, Y)):
        logger.debug(f"Fold {fold+1}/{n_splits}: train={len(train_idx)} val={len(val_idx)}")
        X_train, X_val = X[train_idx], X[val_idx]
        Y_train, Y_val = Y[train_idx], Y[val_idx]

        clf = clone(base_model)
        clf.fit(X_train, Y_train)

        Y_pred = clf.predict(X_val)
        Y_proba = None
        if hasattr(clf, "predict_proba"):
            try:
                Y_proba = clf.predict_proba(X_val)
            except Exception as exc:
                logger.debug(f"predict_proba failed: {exc}")

        fold_scores.append(_fold_metrics(Y_val, Y_pred, Y_proba))

    df = pd.DataFrame(fold_scores)
    mean = df.mean().add_suffix("_mean")
    std = df.std(ddof=0).add_suffix("_std")
    out = pd.concat([mean, std])
    out["model"] = name
    logger.info("[green]✓[/] %s – subset-acc %.3f ± %.3f | f1-macro %.3f ± %.3f",
                name, out["subset_acc_mean"], out["subset_acc_std"],
                out["f1_macro_mean"], out["f1_macro_std"])
    return out

# Run multiple models
def run_all_models(X: np.ndarray,
                   Y: np.ndarray,
                   model_names: List[str],
                   n_splits: int) -> pd.DataFrame:
    results = [
        evaluate_model(name, MODEL_REGISTRY[name], X, Y, n_splits)
        for name in model_names
    ]
    return (
        pd.DataFrame(results)
        .set_index("model")
        .sort_values("f1_macro_mean", ascending=False)
        .round(4)
    )

# Data loading helper
def _load_data(path: Path) -> Tuple[np.ndarray, np.ndarray]:
    suffix = path.suffix.lower()
    if suffix in {".joblib", ".pkl", ".pickle"}:
        obj = joblib.load(path)
        if isinstance(obj, (list, tuple)) and len(obj) == 2:
            X, Y = obj  # type: ignore
        elif isinstance(obj, dict) and {"X", "Y"}.issubset(obj):
            X, Y = obj["X"], obj["Y"]  # type: ignore
        else:
            raise ValueError("Joblib file must contain (X, Y) tuple or dict with keys 'X' and 'Y'.")
    elif suffix == ".npz":
        npz = np.load(path)
        if {"X", "Y"}.issubset(npz):
            X, Y = npz["X"], npz["Y"]
        else:
            raise ValueError("NPZ must contain 'X' and 'Y' arrays.")
    else:
        raise ValueError("Unsupported file extension. Use .joblib, .pkl, .pickle, or .npz.")

    X_arr, Y_arr = np.asarray(X), np.asarray(Y)
    if Y_arr.ndim == 1:
        raise ValueError("Y must be 2-D multi-label matrix (n_samples, n_classes).")
    return X_arr, Y_arr

# CLI entrypoint
@click.command(context_settings={"show_default": True})
@click.option("--data", "data_path", type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to joblib/pkl/npz file containing X and Y.")
@click.option("--splits", default=5, show_default=True, help="Number of CV folds.")
@click.option("--output", "output_path", type=click.Path(path_type=Path), default="multilabel_cv_results.csv",
              help="Where to save the results table (CSV or JSON by extension).")
@click.option("--models", "model_names", multiple=True, type=click.Choice(sorted(MODEL_REGISTRY.keys())),
              help="Subset of model names to evaluate. If omitted, run all.")
def cli(data_path: Path, splits: int, output_path: Path, model_names: Tuple[str]):
    """Evaluate multi-label classifiers with cross-validation."""
    try:
        X, Y = _load_data(data_path)
    except Exception as exc:
        logger.error(f"Data loading failed: {exc}")
        sys.exit(1)

    names_to_run = list(model_names) if model_names else list(MODEL_REGISTRY.keys())
    logger.info(f"Evaluating {len(names_to_run)} model(s): {', '.join(names_to_run)}")

    results_df = run_all_models(X, Y, names_to_run, splits)
    logger.info("Top-3 models by f1-macro:\n%s", results_df.head(3).to_markdown())

    # save results
    if output_path.suffix.lower() == ".json":
        results_df.to_json(output_path, orient="table", index=True)
    else:
        results_df.to_csv(output_path)
    logger.success(f"Results saved to {output_path}")

if __name__ == "__main__":
    cli()
