"""
Usage:
```python
from EvalCV import evaluate_models, models
# prepare X (DataFrame/array), y (Series/1D array), num_cols, cat_cols
results = evaluate_models(
    X, y, models,
    num_cols=num_cols,
    cat_cols=cat_cols,
    n_splits=5
)
print(results)
```"""

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, f1_score,
    precision_score, recall_score,
    classification_report, confusion_matrix
)

# tqdm for progress bars
from tqdm.auto import tqdm
# Base classifiers
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    HistGradientBoostingClassifier
)
from xgboost import XGBClassifier
# Base classifiers
to_list = [
    (LogisticRegression(class_weight='balanced', max_iter=1000), 'lr_clf'),
    (SVC(class_weight='balanced', probability=False, kernel='rbf'), 'svm_rbf_clf'),
    (KNeighborsClassifier(n_neighbors=3), 'knn3_clf'),
    (KNeighborsClassifier(n_neighbors=5), 'knn5_clf'),
    (KNeighborsClassifier(n_neighbors=7), 'knn7_clf'),
    (GaussianNB(), 'gnb_clf'),
    (DecisionTreeClassifier(class_weight='balanced'), 'dt_clf'),
    (RandomForestClassifier(class_weight='balanced', n_jobs=-1), 'rfc_clf'),
    (ExtraTreesClassifier(class_weight='balanced', n_jobs=-1), 'etc_clf'),
    (GradientBoostingClassifier(), 'gbc_clf'),
    (HistGradientBoostingClassifier(class_weight='balanced'), 'hgb_clf'),
    (XGBClassifier(learning_rate=0.1, objective='multi:softprob', n_jobs=-1), 'xgb_clf'),
]

models = to_list

# Preprocessor factory

def make_preprocessor(num_cols, cat_cols):
    return ColumnTransformer([
        ('num', StandardScaler(), num_cols),
        ('cat', OneHotEncoder(handle_unknown='ignore'), cat_cols)
    ])

# Evaluation function

def evaluate_models(X, y, models, num_cols=None, cat_cols=None,
                    n_splits=5, random_state=42):
    """
    Runs multiclass StratifiedKFold CV, returns DataFrame of mean/std metrics.
    Shows tqdm progress bar for model loop.
    Prints classification report and confusion matrix per model.
    """
    # detect DataFrame vs array
    is_df = isinstance(X, pd.DataFrame)
    X_arr = X.values if is_df else np.asarray(X)
    y_arr = y.values.ravel() if hasattr(y, 'values') else np.asarray(y).ravel()

    # CV splitter
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    results = []
    # model loop with tqdm
    for clf, name in tqdm(models, desc='Evaluating models'):
        accs, f1s, precs, recs = [], [], [], []
        all_y_true, all_y_pred = [], []

        # fold loop
        for train_idx, test_idx in skf.split(X_arr, y_arr):
            # slice X
            if is_df:
                X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
            else:
                X_tr, X_te = X_arr[train_idx], X_arr[test_idx]
            y_tr, y_te = y_arr[train_idx], y_arr[test_idx]

            # pipeline assembly
            steps = []
            if is_df and (num_cols or cat_cols):
                steps.append(('pre', make_preprocessor(num_cols, cat_cols)))
            steps.append(('clf', clf))
            pipe = Pipeline(steps)

            # fit & predict
            pipe.fit(X_tr, y_tr)
            y_pred = pipe.predict(X_te)

            all_y_true.append(y_te)
            all_y_pred.append(y_pred)

            # compute metrics
            accs.append(accuracy_score(y_te, y_pred))
            f1s.append(f1_score(y_te, y_pred, average='macro', zero_division=0))
            precs.append(precision_score(y_te, y_pred, average='macro', zero_division=0))
            recs.append(recall_score(y_te, y_pred, average='macro', zero_division=0))

        # full predictions
        y_true_full = np.concatenate(all_y_true)
        y_pred_full = np.concatenate(all_y_pred)

        # detailed report
        print(f"\n=== Model: {name} ===")
        print("Classification Report:")
        print(classification_report(y_true_full, y_pred_full, zero_division=0))
        print("Confusion Matrix:")
        print(confusion_matrix(y_true_full, y_pred_full))

        # aggregate results
        row = {
            'model': name,
            'accuracy_mean': np.mean(accs), 'accuracy_std': np.std(accs),
            'f1_mean': np.mean(f1s),         'f1_std': np.std(f1s),
            'precision_mean': np.mean(precs), 'precision_std': np.std(precs),
            'recall_mean': np.mean(recs),     'recall_std': np.std(recs)
        }
        results.append(row)

    return pd.DataFrame(results)

