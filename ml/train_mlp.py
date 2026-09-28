#!/usr/bin/env python3
"""ml/train_mlp.py — minimal offline MLP for the AI-SOC deep-learning component.

Trains a small neural network (input -> Dense64 ReLU -> Dense32 ReLU -> sigmoid)
to classify CICIDS2017 CICFlowMeter flows as BENIGN vs ATTACK. Purely OFFLINE:
this is an evaluation artifact that satisfies the project's "Deep Learning"
requirement (docs/project-plan-updated.md section 6). It is deliberately NOT
wired into the live detection pipeline — the runtime architecture is frozen.

numpy-only on purpose: scikit-learn / torch / pandas are not installed on this
box (Python 3.14), and a hand-rolled net with explicit forward/backprop is more
defensible for a capstone than a one-line library .fit(). Figures use matplotlib.

Outputs:
  data/ml_eval.json          — architecture, features, split sizes, metrics, CM
  docs/figures/mlp_confusion_matrix.png
  docs/figures/mlp_training_loss.png

Usage: python3 ml/train_mlp.py [--per-file N] [--epochs E] [--seed S]
       (defaults keep training fast: subsamples flows, ~a minute total)
"""
import csv, os, sys, json, math, random, argparse
from datetime import datetime, timezone

import numpy as np

csv.field_size_limit(1 << 24)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CICIDS_DIR = os.path.join(ROOT, "data", "cicids")
FIG_DIR = os.path.join(ROOT, "docs", "figures")
OUT_JSON = os.path.join(ROOT, "data", "ml_eval.json")

FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",           # brute force
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",  # DDoS
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",    # botnet
]

# identifier / leakage / non-numeric columns dropped before training
# (names are whitespace-stripped; CICFlowMeter prepends spaces to many headers)
DROP = {
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp",
    "Label", "Fwd Header Length.1",
}
# APPEND-MARKER

def _to_float(v):
    """CICFlowMeter cells: floats, ints, 'Infinity', 'NaN', or blanks."""
    try:
        f = float(v)
    except (ValueError, TypeError):
        return math.nan
    if math.isinf(f):
        return math.nan
    return f


def load_samples(per_file, seed):
    """Stream each CICIDS CSV once, reservoir-sample up to `per_file` rows PER
    CLASS (benign / attack) so the training set is balanced and small. Returns
    (feature_names, X list-of-lists, y list). Uses stdlib csv only (latin-1)."""
    rng = random.Random(seed)
    feat_cols = None            # locked from the first file's header
    label_key = None
    # reservoirs: per file+class capped sample of (row-values) tuples
    Xs, ys = [], []
    for fname in FILES:
        path = os.path.join(CICIDS_DIR, fname)
        if not os.path.exists(path):
            print(f"  ! missing {fname}, skipping", file=sys.stderr)
            continue
        res = {0: [], 1: []}     # class -> list of feature-vectors
        seen = {0: 0, 1: 0}
        with open(path, "r", encoding="latin-1", newline="") as fh:
            reader = csv.reader(fh)
            header = [h.strip() for h in next(reader)]
            idx = {h: i for i, h in enumerate(header)}
            if label_key is None:
                label_key = "Label" if "Label" in idx else header[-1]
            if feat_cols is None:
                feat_cols = [h for h in header if h and h not in DROP]
            li = idx.get(label_key, len(header) - 1)
            fis = [idx[c] for c in feat_cols]
            for row in reader:
                if len(row) <= li:
                    continue
                lab = 0 if row[li].strip().upper() == "BENIGN" else 1
                seen[lab] += 1
                vec = [_to_float(row[i]) if i < len(row) else math.nan for i in fis]
                # reservoir sampling keeps a uniform sample without full load
                buf = res[lab]
                if len(buf) < per_file:
                    buf.append(vec)
                else:
                    j = rng.randint(0, seen[lab] - 1)
                    if j < per_file:
                        buf[j] = vec
        for lab in (0, 1):
            for vec in res[lab]:
                Xs.append(vec); ys.append(lab)
        print(f"  {fname}: benign={seen[0]} attack={seen[1]} "
              f"-> sampled {len(res[0])}+{len(res[1])}", file=sys.stderr)
    return feat_cols, Xs, ys
# PREP-MARKER

def preprocess(X, feat_names):
    """np array, impute NaN with column median, drop zero-variance columns,
    z-score standardize. Returns (X_std, kept_names, medians, mean, std)."""
    A = np.asarray(X, dtype=np.float64)
    med = np.nanmedian(A, axis=0)
    med = np.where(np.isnan(med), 0.0, med)
    inds = np.where(np.isnan(A))
    A[inds] = np.take(med, inds[1])
    std = A.std(axis=0)
    keep = std > 1e-8                       # drop constant columns
    A = A[:, keep]
    kept = [n for n, k in zip(feat_names, keep) if k]
    mean = A.mean(axis=0)
    sd = A.std(axis=0); sd[sd < 1e-8] = 1.0
    return (A - mean) / sd, kept, med[keep], mean, sd


def split(X, y, seed, test_frac=0.3):
    """Stratified train/test split."""
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    tr_idx, te_idx = [], []
    for c in (0, 1):
        idx = np.where(y == c)[0]
        rng.shuffle(idx)
        cut = int(len(idx) * (1 - test_frac))
        tr_idx += list(idx[:cut]); te_idx += list(idx[cut:])
    rng.shuffle(tr_idx); rng.shuffle(te_idx)
    tr_idx = np.array(tr_idx); te_idx = np.array(te_idx)
    return X[tr_idx], y[tr_idx], X[te_idx], y[te_idx]
# MLP-MARKER

class MLP:
    """input -> Dense(64) ReLU -> Dense(32) ReLU -> Dense(1) sigmoid.
    Binary cross-entropy loss, Adam optimizer, minibatch. Pure numpy."""

    def __init__(self, n_in, seed=0, h1=64, h2=32):
        rng = np.random.default_rng(seed)
        # He initialization for ReLU layers
        self.W1 = rng.standard_normal((n_in, h1)) * math.sqrt(2 / n_in)
        self.b1 = np.zeros(h1)
        self.W2 = rng.standard_normal((h1, h2)) * math.sqrt(2 / h1)
        self.b2 = np.zeros(h2)
        self.W3 = rng.standard_normal((h2, 1)) * math.sqrt(2 / h2)
        self.b3 = np.zeros(1)
        self.arch = f"{n_in} -> Dense{h1}+ReLU -> Dense{h2}+ReLU -> Dense1+Sigmoid"
        self._m = {}; self._v = {}; self._t = 0
        for k in ("W1", "b1", "W2", "b2", "W3", "b3"):
            self._m[k] = np.zeros_like(getattr(self, k))
            self._v[k] = np.zeros_like(getattr(self, k))

    def forward(self, X):
        self.z1 = X @ self.W1 + self.b1; self.a1 = np.maximum(0, self.z1)
        self.z2 = self.a1 @ self.W2 + self.b2; self.a2 = np.maximum(0, self.z2)
        self.z3 = self.a2 @ self.W3 + self.b3
        self.out = 1 / (1 + np.exp(-np.clip(self.z3, -30, 30)))
        return self.out.ravel()

    def _adam(self, grads, lr=1e-3, b1=0.9, b2=0.999, eps=1e-8):
        self._t += 1
        for k, gk in grads.items():
            self._m[k] = b1 * self._m[k] + (1 - b1) * gk
            self._v[k] = b2 * self._v[k] + (1 - b2) * (gk * gk)
            mhat = self._m[k] / (1 - b1 ** self._t)
            vhat = self._v[k] / (1 - b2 ** self._t)
            setattr(self, k, getattr(self, k) - lr * mhat / (np.sqrt(vhat) + eps))

    def step(self, X, y, lr):
        n = len(y); p = self.forward(X); yv = y.reshape(-1, 1)
        pv = self.out
        dz3 = (pv - yv) / n
        gW3 = self.a2.T @ dz3; gb3 = dz3.sum(0)
        da2 = dz3 @ self.W3.T; dz2 = da2 * (self.z2 > 0)
        gW2 = self.a1.T @ dz2; gb2 = dz2.sum(0)
        da1 = dz2 @ self.W2.T; dz1 = da1 * (self.z1 > 0)
        gW1 = X.T @ dz1; gb1 = dz1.sum(0)
        self._adam({"W1": gW1, "b1": gb1, "W2": gW2, "b2": gb2,
                    "W3": gW3, "b3": gb3}, lr)
        eps = 1e-9
        return float(-np.mean(yv * np.log(pv + eps) + (1 - yv) * np.log(1 - pv + eps)))
# TRAIN-MARKER

def train(model, Xtr, ytr, epochs, batch=256, lr=1e-3, seed=0):
    rng = np.random.default_rng(seed)
    n = len(ytr); losses = []
    for ep in range(epochs):
        idx = rng.permutation(n); el = 0.0; nb = 0
        for s in range(0, n, batch):
            bi = idx[s:s + batch]
            el += model.step(Xtr[bi], ytr[bi], lr); nb += 1
        losses.append(el / max(nb, 1))
        print(f"  epoch {ep+1}/{epochs}  loss={losses[-1]:.4f}", file=sys.stderr)
    return losses


def metrics(y, p, thr=0.5):
    yh = (p >= thr).astype(int); y = np.asarray(y)
    tp = int(((yh == 1) & (y == 1)).sum()); tn = int(((yh == 0) & (y == 0)).sum())
    fp = int(((yh == 1) & (y == 0)).sum()); fn = int(((yh == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / len(y) if len(y) else 0.0
    # ROC-AUC via rank statistic (Mann–Whitney U)
    order = np.argsort(p); ranks = np.empty(len(p)); ranks[order] = np.arange(1, len(p) + 1)
    npos = int((y == 1).sum()); nneg = len(y) - npos
    auc = ((ranks[y == 1].sum() - npos * (npos + 1) / 2) / (npos * nneg)) if npos and nneg else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4), "accuracy": round(acc, 4),
            "roc_auc": round(float(auc), 4)}


def plot_cm(m, path):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["Pred benign", "Pred attack"])
    ax.set_yticks([0, 1], ["True benign", "True attack"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=11)
    ax.set_title(f"MLP confusion matrix  (F1={m['f1']}, AUC={m['roc_auc']})", fontsize=10)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_loss(losses, path):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(4.6, 3.2))
    ax.plot(range(1, len(losses) + 1), losses, marker="o", ms=3)
    ax.set_xlabel("epoch"); ax.set_ylabel("train BCE loss")
    ax.set_title("MLP training loss", fontsize=10)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
# MAIN-MARKER

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-file", type=int, default=20000,
                    help="max rows sampled per class per file")
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    print("loading + sampling CICIDS flows…", file=sys.stderr)
    feat_cols, X, y = load_samples(args.per_file, args.seed)
    if not X:
        print(json.dumps({"error": "no data (CICIDS CSVs missing?)"})); return
    print(f"total samples: {len(y)}  benign={y.count(0)} attack={y.count(1)}",
          file=sys.stderr)

    Xs, kept, _, _, _ = preprocess(X, feat_cols)
    Xtr, ytr, Xte, yte = split(Xs, y, args.seed)
    print(f"features: {len(kept)}  train={len(ytr)} test={len(yte)}", file=sys.stderr)

    model = MLP(Xs.shape[1], seed=args.seed)
    losses = train(model, Xtr, ytr, args.epochs, lr=args.lr, seed=args.seed)
    m = metrics(yte, model.forward(Xte))
    print(f"TEST  P={m['precision']} R={m['recall']} F1={m['f1']} "
          f"AUC={m['roc_auc']} ACC={m['accuracy']}", file=sys.stderr)

    os.makedirs(FIG_DIR, exist_ok=True)
    plot_cm(m, os.path.join(FIG_DIR, "mlp_confusion_matrix.png"))
    plot_loss(losses, os.path.join(FIG_DIR, "mlp_training_loss.png"))

    out = {
        "model": "MLP (binary flow classifier, BENIGN vs ATTACK)",
        "architecture": model.arch,
        "framework": "numpy (hand-implemented forward/backprop, Adam)",
        "optimizer": "Adam", "loss": "binary cross-entropy",
        "epochs": args.epochs, "learning_rate": args.lr, "seed": args.seed,
        "dataset": "CICIDS2017 (CICFlowMeter flows: brute-force, DDoS, botnet days)",
        "n_features": len(kept), "features": kept,
        "split": {"train": len(ytr), "test": len(yte), "test_frac": 0.3,
                  "stratified": True},
        "class_balance": {"benign": int(np.sum(np.asarray(y) == 0)),
                          "attack": int(np.sum(np.asarray(y) == 1))},
        "test_metrics": m,
        "confusion_matrix": {"tn": m["tn"], "fp": m["fp"], "fn": m["fn"], "tp": m["tp"]},
        "figures": ["docs/figures/mlp_confusion_matrix.png",
                    "docs/figures/mlp_training_loss.png"],
        "final_train_loss": round(losses[-1], 4) if losses else None,
        "note": "Offline evaluation artifact for the Deep Learning requirement; "
                "NOT wired into the live detection pipeline (architecture frozen).",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"wrote {OUT_JSON} + 2 figures", file=sys.stderr)
    print(json.dumps(out["test_metrics"]))


if __name__ == "__main__":
    main()


