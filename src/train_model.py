import os
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
import joblib

from feature_extractor import extract_features

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, 'data', 'dataset.csv')
    model_dir = os.path.join(base_dir, 'model')
    model_path = os.path.join(model_dir, 'phishing_model.pkl')
    comparison_path = os.path.join(model_dir, 'model_comparison.json')
    
    print(f"Loading dataset from {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except FileNotFoundError:
        print(f"Error: Dataset not found at {data_path}")
        return

    print("Extracting features...")
    features_list = []
    for url in df['URL']:
        features_list.append(extract_features(url))
    
    features_df = pd.DataFrame(features_list)
    feature_names = features_df.columns.tolist()
    
    X = features_df.values
    y = df['label'].values
    
    print("Splitting dataset into train and test sets (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'Decision Tree': DecisionTreeClassifier(random_state=42),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'SVM': SVC(probability=True, random_state=42),
        'Gradient Boosting': GradientBoostingClassifier(random_state=42)
    }
    
    results = {}
    best_model_name = None
    best_roc_auc = -1
    best_f1 = -1
    best_recall = -1
    
    print("\nTraining and evaluating models...\n")
    print(f"{'Model':<20} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8}")
    print("-" * 75)
    
    for name, clf in models.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_prob)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        results[name] = {
            'Accuracy': acc,
            'Precision': prec,
            'Recall': rec,
            'F1': f1,
            'ROC-AUC': roc_auc,
            'ConfusionMatrix': cm
        }
        
        print(f"{name:<20} | {acc:.4f}   | {prec:.4f}    | {rec:.4f}   | {f1:.4f}   | {roc_auc:.4f}")
        
        # Selection logic
        # If ROC-AUC is significantly better (by > 0.0001)
        if roc_auc > best_roc_auc + 0.0001:
            best_model_name = name
            best_roc_auc = roc_auc
            best_f1 = f1
            best_recall = rec
        elif abs(roc_auc - best_roc_auc) <= 0.0001:
            # Tie on ROC-AUC, prefer better F1
            if f1 > best_f1 + 0.0001:
                best_model_name = name
                best_roc_auc = roc_auc
                best_f1 = f1
                best_recall = rec
            elif abs(f1 - best_f1) <= 0.0001:
                # Tie on F1, prefer better Recall
                if rec > best_recall + 0.0001:
                    best_model_name = name
                    best_roc_auc = roc_auc
                    best_f1 = f1
                    best_recall = rec
                elif abs(rec - best_recall) <= 0.0001:
                    # Tie on everything, prefer simpler model.
                    # Simplicity order: Logistic Regression > Decision Tree > SVM > Random Forest > Gradient Boosting
                    simplicity_rank = {
                        'Logistic Regression': 1,
                        'Decision Tree': 2,
                        'SVM': 3,
                        'Random Forest': 4,
                        'Gradient Boosting': 5
                    }
                    if best_model_name and simplicity_rank[name] < simplicity_rank[best_model_name]:
                        best_model_name = name
                        best_roc_auc = roc_auc
                        best_f1 = f1
                        best_recall = rec

    print("-" * 75)
    print(f"\nSelected Production Model: {best_model_name}")
    
    # Save comparison
    os.makedirs(model_dir, exist_ok=True)
    with open(comparison_path, 'w') as f:
        json.dump({
            'selected_model': best_model_name,
            'metrics': results
        }, f, indent=4)
        
    print(f"Comparison results saved to {comparison_path}")
    
    # Save best model
    best_clf = models[best_model_name]
    joblib.dump({'model': best_clf, 'feature_names': feature_names}, model_path)
    print(f"Production model saved to {model_path}")
    
    if best_model_name == 'Logistic Regression':
        feature_importance_path = os.path.join(model_dir, 'feature_importance.json')
        coefficients = best_clf.coef_[0]
        
        importance_data = []
        for feature_name, coef in zip(feature_names, coefficients):
            importance_data.append({
                "feature": feature_name,
                "coefficient": float(round(coef, 4)),
                "importance": float(round(abs(coef), 4)),
                "direction": "increases_phishing_risk" if coef > 0 else "decreases_phishing_risk"
            })
            
        importance_data.sort(key=lambda x: x['importance'], reverse=True)
        
        with open(feature_importance_path, 'w') as f:
            json.dump(importance_data, f, indent=4)
        print(f"Feature importance saved to {feature_importance_path}")
        
    print("Training complete.")

if __name__ == "__main__":
    main()
