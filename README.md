# 反欺诈规则研究平台（第一版）

本项目只处理显式标注的虚构交易和身份关联事件，不连接真实账户、支付渠道或生产数据。

## 能力

- 规则版本：每条规则携带 `rule_id` 和 `version`，证据保留完整规则版本。
- 事件来源：事件信封包含来源系统、生产者和来源元数据。
- 时序窗口：按固定时间窗口识别跨多个关联身份的异常交易模式。
- 乱序修正：窗口封存前，迟到事件会触发同一命中的重新计算和更新。
- 撤销传播：交易事件被撤销后，依赖该交易的命中会转为 `revoked`。
- 命中证据：保存身份、交易、身份关联以及具体触发事件，不只输出风险分。
- 重叠人工判断：同一证据可同时存在误报排除、身份拆分和规则例外，各自带独立判断 ID。
- 人工撤回恢复：只撤回指定判断并恢复它实际影响的金额或身份链，其他判断继续生效。
- 命中解释：当前证据同时保留原始交易/关联、生效交易/关联、规则版本和有效人工决定。
- 历史重评：开放窗口内迟到资料继续修正当前命中；封存后的证据、人工或规则变化另成版本。
- 原因区分：每次变化标记为 `evidence`、`manual`、`rule` 或 `seal`。
- 模型扩展：`HeuristicModel` 是确定性占位模型，可将分数附加到规则证据。
- 跨案件归属：`CaseBook` 允许多个案件引用同一原始交易，但只有明确归属的份额计入案件总额。
- 争议份额：超出原始金额的重叠认领保留为 `disputed_amount`，单独展示，不会被最后一次操作覆盖。
- 采纳前预览：份额划分、部分转移与案件合并在采纳前返回 `AttributionImpact`，列明金额、命中规则与受影响的人工判断。
- 撤回保留：撤回单份归属决定只移除它自己的条目，其余案件已确认范围继续保留；合并撤回会恢复来源案件。
- 封存迟到证据：封存案件的新归属形成新的 `CaseSnapshot` 修订，封存快照与历次调查解释仍可独立查看。
- 金额复演：`CaseBook.reconcile()` 逐笔给出原始金额、已确认、争议与未归属金额，合计回到原交易金额。

## 快速验证

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m antifraud.examples.demo
```

## 案件归属

```python
from antifraud.cases import CaseBook

book = CaseBook(engine)
book.open_case("case-alpha")
book.open_case("case-beta")

# 采纳前先预览：金额、命中规则与已有人工判断受影响的位置
preview = book.propose_share(
    "case-alpha",
    {"evt-t1": 600.0},
    operator="analyst-1",
    rationale="alpha claim",
)
print(preview.lines)
print(preview.affected_hits)
print(preview.affected_manual_judgments)

# 部分认领；重叠部分进入 disputed_amount 而不是覆盖已有归属
book.adopt_share(
    "case-alpha", {"evt-t1": 600.0},
    operator="analyst-1", rationale="alpha claim",
    decided_at=300, decision_id="alpha-t1",
)
book.adopt_transfer(
    "case-alpha", "case-beta", {"evt-t2": 150.0},
    operator="analyst-2", rationale="move part of t2",
    decided_at=350, decision_id="move-t2",
)
book.adopt_merge(
    "case-beta", "case-alpha",
    operator="lead", rationale="consolidate cases",
    decided_at=360, decision_id="merge-beta",
)

# 撤回单份决定，其他案件已确认范围不变
book.withdraw_decision("move-t2", withdrawn_at=370, reason="cancelled")

# 封存后迟到证据形成新修订；原封存快照保留
snapshot = book.seal_case("case-alpha", sealed_at=400)
original = book.case_explanation("case-alpha", revision=1)

for event_id, original_amount, confirmed, disputed, unattributed in book.reconcile():
    assert round(confirmed + disputed + unattributed, 6) == original_amount
```

## 基本用法

```python
from antifraud.engine import RuleEngine
from antifraud.events import (
    IdentityAssociation,
    Transaction,
    association_event,
    transaction_event,
)
from antifraud.models import EventSource
from antifraud.rules import CrossIdentityFlowRule

source = EventSource(system="fictitious-lab")
engine = RuleEngine([
    CrossIdentityFlowRule(
        window_seconds=300,
        min_identities=3,
        min_total_amount=900,
    )
])

decisions = engine.ingest_many([
    association_event(IdentityAssociation("l1", "A", "B", 0), source=source),
    association_event(IdentityAssociation("l2", "B", "C", 0), source=source),
    transaction_event(Transaction("t1", "A", "B", 500), occurred_at=100, source=source),
    transaction_event(Transaction("t2", "B", "C", 500), occurred_at=200, source=source),
])

for decision in decisions:
    print(decision.evidence.rule.qualified_name)
    print(decision.evidence.trigger_events)

# 人工否定一条证据，再撤回该人工判断
engine.exclude_evidence(
    "evt-t1",
    "transaction disputed by analyst",
    operator="analyst-1",
    decided_at=250,
)
engine.grant_rule_exception(
    "evt-t1",
    "accepted merchant case",
    operator="analyst-2",
    decided_at=270,
    judgment_id="exception-t1",
)
engine.withdraw_manual_judgment(
    "exception-t1",
    withdrawn_at=280,
    reason="exception no longer applies",
)
engine.withdraw_evidence_judgment(
    "evt-t1",
    withdrawn_at=260,
    reason="evidence verified",
)
explanation = engine.explain_hit(engine.active_hits()[0].hit_id)
print(explanation.original_transactions)
print(explanation.active_manual_judgments)

# 用新版本规则重算，历史记录保留变化原因
engine.replace_rule(
    "cross_identity_flow",
    CrossIdentityFlowRule(
        version="v2",
        window_seconds=300,
        min_identities=3,
        min_total_amount=1200,
    ),
)
for revision in engine.hit_history():
    print(revision["cause"], revision["current"].hit_id)
```

## 决策状态

- `open`：当前有效且仍可被窗口内事件修正。
- `updated`：本次摄入导致尚未封存的证据变化。
- `revoked`：撤销或有效事件重算后，该命中不再成立。
- `sealed`：水位已超过窗口边界，结果作为不可变快照保留。
- `revised`：封存后的重评结果；原 `sealed` 快照继续保留。
