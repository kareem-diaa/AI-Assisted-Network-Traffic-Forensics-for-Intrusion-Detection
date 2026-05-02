"""
predict_pcap.py — Run a saved IDS model against a PCAP file.

Pipeline:
  PCAP  ──► CICFlowMeter (cicflowmeter)  ──► flows CSV
         ──► feature selection + scaling
         ──► model.predict()
         ──► results printed + saved to <pcap_name>_predictions.csv

Requirements:
    pip install cicflowmeter pandas numpy scikit-learn joblib

Usage:
    python3 predict_pcap.py --pcap ../pcap/attack_scan.pcap \
                            --model ids_model.pkl \
                            --scaler scaler.pkl \
                            --features feature_names.pkl

All --model / --scaler / --features arguments default to files in the
same directory as this script, so the minimal call is just:
    python3 predict_pcap.py --pcap ../pcap/attack_scan.pcap
"""

import argparse
import os
import sys
import subprocess
import tempfile

import numpy as np
import pandas as pd
import joblib


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    p = argparse.ArgumentParser(description="Predict intrusions from a PCAP file.")
    p.add_argument("--pcap",     required=True,  help="Path to the input .pcap file")
    p.add_argument("--model",    default=os.path.join(SCRIPT_DIR, "ids_model.pkl"),
                   help="Path to the saved model .pkl (default: ml/ids_model.pkl)")
    p.add_argument("--scaler",   default=os.path.join(SCRIPT_DIR, "scaler.pkl"),
                   help="Path to the saved scaler .pkl (default: ml/scaler.pkl)")
    p.add_argument("--features", default=os.path.join(SCRIPT_DIR, "feature_names.pkl"),
                   help="Path to feature_names.pkl produced by ids_model.py "
                        "(default: ml/feature_names.pkl)")
    p.add_argument("--output",   default=None,
                   help="Output CSV path (default: <pcap_stem>_predictions.csv)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# PCAP → flows CSV via cicflowmeter
# ---------------------------------------------------------------------------

def pcap_to_flows(pcap_path: str, out_csv: str) -> None:
    """
    Calls the cicflowmeter CLI to convert a PCAP into a CIC-IDS2017-style
    flows CSV.  Install with:  pip install cicflowmeter
    """
    print(f"[1/4] Extracting flows from {pcap_path} ...")
    result = subprocess.run(
        ["cicflowmeter", "-f", pcap_path, "-c", out_csv],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("ERROR: cicflowmeter failed.\n"
              "  Install it with:  pip install cicflowmeter\n"
              f"  stderr: {result.stderr.strip()}")
        sys.exit(1)
    if not os.path.exists(out_csv) or os.path.getsize(out_csv) == 0:
        print("ERROR: cicflowmeter produced no output. "
              "The PCAP may be empty or unreadable.")
        sys.exit(1)
    print(f"  → Flows written to {out_csv}")


# ---------------------------------------------------------------------------
# Feature normalisation helpers
# ---------------------------------------------------------------------------

# CICFlowMeter sometimes uses slightly different column name styles
# (spaces vs underscores, capitalisation).  We normalise everything to
# lower-case with underscores so the lookup is robust.

def _normalise(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("/", "_per_")


def align_features(df: pd.DataFrame, feature_names: list) -> pd.DataFrame:
    """
    Select and return exactly the columns required by the model, doing
    best-effort fuzzy matching if the CSV uses a different naming style.
    """
    # Build a map:  normalised_name -> actual_csv_column
    norm_to_col = {_normalise(c): c for c in df.columns}

    selected = {}
    missing = []
    for feat in feature_names:
        norm = _normalise(feat)
        if feat in df.columns:
            selected[feat] = df[feat]
        elif norm in norm_to_col:
            selected[feat] = df[norm_to_col[norm]].values
        else:
            missing.append(feat)

    if missing:
        print(f"WARNING: {len(missing)} feature(s) not found in the flow CSV "
              f"and will be filled with 0:\n  {missing}\n"
              "  This usually means the cicflowmeter version outputs slightly "
              "different column names.  Results may be less accurate.")
        for feat in missing:
            selected[feat] = 0.0

    return pd.DataFrame(selected, columns=feature_names)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # -- Validate inputs -----------------------------------------------------
    for label, path in [("PCAP", args.pcap),
                         ("Model", args.model),
                         ("Scaler", args.scaler)]:
        if not os.path.exists(path):
            print(f"ERROR: {label} file not found: {path}")
            sys.exit(1)

    feature_names = None
    if os.path.exists(args.features):
        feature_names = joblib.load(args.features)
        print(f"[0/4] Loaded {len(feature_names)} feature names from {args.features}")
    else:
        print(f"WARNING: feature_names.pkl not found at {args.features}.\n"
              "  Re-run ids_model.py (updated version) to generate it, then\n"
              "  copy ids_model.pkl, scaler.pkl, and feature_names.pkl here.\n"
              "  Continuing — will attempt to use ALL numeric columns instead.")

    # -- Step 1: PCAP → flows CSV --------------------------------------------
    pcap_stem = os.path.splitext(os.path.basename(args.pcap))[0]
    output_csv = args.output or os.path.join(
        os.path.dirname(os.path.abspath(args.pcap)),
        f"{pcap_stem}_predictions.csv"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        flows_csv = os.path.join(tmpdir, "flows.csv")
        pcap_to_flows(args.pcap, flows_csv)

        # -- Step 2: load & clean flows --------------------------------------
        print("[2/4] Loading and cleaning flows ...")
        df = pd.read_csv(flows_csv, low_memory=False)
        df.columns = df.columns.str.strip()
        print(f"  → {len(df)} flows, {df.shape[1]} columns")

        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Keep metadata columns for the output report
        meta_cols = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port",
                     "Protocol", "Timestamp",
                     # alternate names used by some cicflowmeter versions
                     "src_ip", "dst_ip", "src_port", "dst_port",
                     "flow_id", "timestamp"]
        meta = df[[c for c in meta_cols if c in df.columns]].copy()

        df.dropna(inplace=True)
        if len(df) == 0:
            print("ERROR: No valid flows remain after removing NaN/Inf rows.")
            sys.exit(1)

        # -- Step 3: feature selection + scaling -----------------------------
        print("[3/4] Selecting features and scaling ...")
        model  = joblib.load(args.model)
        scaler = joblib.load(args.scaler)

        if feature_names is not None:
            X = align_features(df, feature_names)
        else:
            # Fallback: use all numeric columns (likely mismatched, low accuracy)
            drop_meta = ["Label", "Flow ID", "Source IP", "Destination IP",
                         "Source Port", "Destination Port", "Timestamp",
                         "src_ip", "dst_ip", "src_port", "dst_port",
                         "flow_id", "timestamp"]
            X = df.drop(columns=[c for c in drop_meta if c in df.columns],
                        errors="ignore").select_dtypes(include=[np.number])
            print(f"  WARNING: using {X.shape[1]} numeric columns as features "
                  "(no feature_names.pkl available). Accuracy will be poor.")

        X = X.fillna(0).replace([np.inf, -np.inf], 0)
        X_scaled = scaler.transform(X)

        # -- Step 4: predict -------------------------------------------------
        print("[4/4] Running predictions ...")
        preds   = model.predict(X_scaled)
        probas  = model.predict_proba(X_scaled)[:, 1]

        labels = pd.Series(preds).map({0: "BENIGN", 1: "ATTACK"})

        # -- Results ---------------------------------------------------------
        result_df = meta.reset_index(drop=True).copy()
        result_df["prediction"]       = labels.values
        result_df["attack_probability"] = probas.round(4)

        n_attack = int((preds == 1).sum())
        n_benign = int((preds == 0).sum())
        total    = len(preds)

        print("\n========================================")
        print("          PREDICTION SUMMARY            ")
        print("========================================")
        print(f"  Total flows analysed : {total}")
        print(f"  BENIGN               : {n_benign}  ({100*n_benign/total:.1f}%)")
        print(f"  ATTACK               : {n_attack}  ({100*n_attack/total:.1f}%)")
        print("========================================\n")

        if n_attack > 0:
            top_attackers = (
                result_df[result_df["prediction"] == "ATTACK"]
                .get("Src IP", result_df.get("src_ip"))
            )
            if top_attackers is not None and not top_attackers.empty:
                print("Top attacker IPs:")
                print(top_attackers.value_counts().head(10).to_string())
                print()

        result_df.to_csv(output_csv, index=False)
        print(f"Full results saved to: {output_csv}")


if __name__ == "__main__":
    main()
