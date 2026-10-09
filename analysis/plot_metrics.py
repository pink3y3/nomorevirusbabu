import json
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns


def plot_metrics(input_path, output_dir):
    input_file = Path(input_path)

    if not input_file.is_file():
        raise FileNotFoundError(f"Metrics file not found: {input_file}")

    data = json.loads(input_file.read_text(encoding="utf-8-sig"))
    metrics = data["metrics"]
    matrix = data["confusion_matrix"]["rows_actual_columns_predicted"]

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # Bar chart of evaluation metrics
    names = ["Accuracy", "Precision", "Recall", "F1-score"]
    values = [
        metrics["accuracy"],
        metrics["precision"],
        metrics["recall"],
        metrics["f1_score"],
    ]

    plt.figure(figsize=(8, 5))
    bars = plt.bar(names, values)
    plt.ylim(0, 1)
    plt.ylabel("Score")
    plt.title("Evaluation Metrics")
    plt.bar_label(bars, fmt="%.2f", padding=3)
    plt.tight_layout()
    plt.savefig(output / "evaluation_metrics.png", dpi=200)
    plt.close()

    # Confusion matrix
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Benign", "Suspicious"],
        yticklabels=["Benign", "Suspicious"],
    )
    plt.xlabel("Predicted label")
    plt.ylabel("Actual label")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(output / "confusion_matrix.png", dpi=200)
    plt.close()

    print(f"Graphs saved in: {output.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot evaluation metrics and confusion matrix."
    )
    parser.add_argument(
        "--input",
        default="analysis/outputs/evaluation_metrics.json",
    )
    parser.add_argument(
        "--output-dir",
        default="analysis/outputs/graphs",
    )
    args = parser.parse_args()
    plot_metrics(args.input, args.output_dir)


if __name__ == "__main__":
    main()