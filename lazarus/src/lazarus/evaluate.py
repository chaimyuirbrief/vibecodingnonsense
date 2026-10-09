"""Classifier evaluation against labeled JSONL reply sets.

Metrics that matter for this domain, in priority order:

1. ``unsafe_opt_out_misses`` — true opt-outs routed somewhere that keeps
   messaging the person (interested/later/not_interested/auto_reply). Target 0.
2. ``opt_out_caught`` — true opt-outs that stop outreach: labeled opt_out, or
   routed to human review (which pauses outreach), or wrong_number (suppressed).
3. ``accuracy`` on decisive predictions, and ``review_rate`` (human workload).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .classify import Classification, classify
from .llm import LLMProvider
from .models import Label

UNSAFE_FOR_OPT_OUT = {Label.INTERESTED, Label.LATER, Label.NOT_INTERESTED, Label.AUTO_REPLY}


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


@dataclass
class EvalReport:
    n: int = 0
    correct: int = 0
    review: int = 0
    llm_calls: int = 0
    by_source: Counter[str] = field(default_factory=Counter)
    confusion: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    unsafe: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    opt_out_total: int = 0
    opt_out_caught: int = 0

    def metrics(self) -> dict[str, Any]:
        labels = [lbl.value for lbl in Label]
        per: dict[str, dict[str, float]] = {}
        for lbl in labels:
            tp = self.confusion[lbl][lbl]
            fn = sum(self.confusion[lbl].values()) - tp
            fp = sum(self.confusion[t][lbl] for t in labels if t != lbl)
            p = tp / (tp + fp) if tp + fp else 0.0
            r = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * p * r / (p + r) if p + r else 0.0
            per[lbl] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3), "support": tp + fn}
        return {
            "n": self.n,
            "accuracy": round(self.correct / self.n, 3) if self.n else 0.0,
            "macro_f1": round(sum(v["f1"] for v in per.values()) / len(per), 3),
            "review_rate": round(self.review / self.n, 3) if self.n else 0.0,
            "opt_out_caught": f"{self.opt_out_caught}/{self.opt_out_total}",
            "unsafe_opt_out_misses": len(self.unsafe),
            "by_source": dict(self.by_source),
            "llm_calls": self.llm_calls,
            "per_label": per,
        }


def evaluate(items: list[dict[str, Any]], llm: LLMProvider | None = None) -> EvalReport:
    rep = EvalReport()
    for it in items:
        truth = Label(it["label"])
        c: Classification = classify(it["text"], llm=llm, first_name=it.get("first_name"))
        rep.n += 1
        rep.by_source[c.source] += 1
        if c.source == "llm" or (c.source == "fallback" and c.llm_error):
            rep.llm_calls += 1
        if c.needs_review:
            rep.review += 1
        rep.confusion[truth.value][c.label.value] += 1
        if c.label is truth:
            rep.correct += 1
        else:
            rep.errors.append({"id": it.get("id"), "text": it["text"], "truth": truth.value, "pred": c.label.value,
                               "review": c.needs_review, "rules": c.rule_ids})
        if truth is Label.OPT_OUT:
            rep.opt_out_total += 1
            if c.label in (Label.OPT_OUT, Label.WRONG_NUMBER) or c.needs_review:
                rep.opt_out_caught += 1
            if c.label in UNSAFE_FOR_OPT_OUT and not c.needs_review:
                rep.unsafe.append({"id": it.get("id"), "text": it["text"], "pred": c.label.value, "rules": c.rule_ids})
    return rep
