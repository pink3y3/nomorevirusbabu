import argparse
import json
from pathlib import Path

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


def evaluate_results(input_path, output_path):
    input_file = Path(input_path)

    if not input_file.is_file():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    data = json.loads(input_file.read_text(encoding="utf-8-sig"))

    if "y_true" not in data or "y_pred" not in data:
        raise ValueError(
            'Input JSON must contain "y_true" and "y_pred" arrays.'
        )

    y_true = data["y_true"]
    y_pred = data["y_pred"]

    if not y_true or len(y_true) != len(y_pred):
        raise ValueError(
            "The label and prediction arrays must be non-empty "
            "and have equal lengths."
        )

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(
        y_true, y_pred, average="binary", zero_division=0
    )
    recall = recall_score(
        y_true, y_pred, average="binary", zero_division=0
    )
    f1 = f1_score(
        y_true, y_pred, average="binary", zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])

    results = {
        "samples_evaluated": len(y_true),
        "metrics": {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
        },
        "confusion_matrix": {
            "labels": [0, 1],
            "rows_actual_columns_predicted": matrix.tolist(),
        },
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=["benign", "suspicious"],
            zero_division=0,
            output_dict=True,
        ),
        "note": (
            "Metrics are meaningful only when labels and predictions "
            "come from a documented evaluation dataset or experiment."
        ),
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    print(f"Samples evaluated: {len(y_true)}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("Confusion matrix (actual rows, predicted columns):")
    print(matrix)
    print(f"Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate binary experiment predictions."
    )
    parser.add_argument(
        "--input",
        default="tests/evaluation_sample.json",
        help="JSON containing y_true and y_pred arrays",
    )
    parser.add_argument(
        "--output",
        default="analysis/outputs/evaluation_metrics.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    try:
        evaluate_results(args.input, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()