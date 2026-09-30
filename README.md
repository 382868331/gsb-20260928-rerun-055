# 反欺诈规则研究平台（第一版）

本项目只处理显式标注的虚构交易和身份关联事件，不连接真实账户、支付渠道或生产数据。

## 能力

- 规则版本：每条规则携带 `rule_id` 和 `version`，证据保留完整规则版本。
- 事件来源：事件信封包含来源系统、生产者和来源元数据。
- 时序窗口：按固定时间窗口识别跨多个关联身份的异常交易模式。
- 乱序修正：窗口封存前，迟到事件会触发同一命中的重新计算和更新。
- 撤销传播：交易事件被撤销后，依赖该交易的命中会转为 `revoked`。
- 命中证据：保存身份、交易、身份关联以及具体触发事件，不只输出风险分。
- 人工证据排除：分析人员可否定交易或身份关联，原始事件仍保留，命中重算并记录理由。
- 人工撤回恢复：撤回人工否定后，系统按当前有效证据恢复原计算。
- 重叠人工判断：同一事件可叠加多条人工判断（误报排除、身份拆分、规则例外等），各自带 `judgment_id` 与 `kind`；撤回其中一条只恢复它实际影响的部分，其余仍生效的判断继续参与计算。
- 规则例外范围：人工判断可通过 `rule_id` 限定只作用于某条规则，其他规则的命中不受影响。
- 命中解释：`explain_hit` 列出原始事件、规则版本、生效与已撤回的人工判断以及相关修订编号，解释金额或身份链变化的原因。
- 撤回顺序无关：最终状态只取决于当前有效判断集合，按不同顺序撤回得到一致结果。
- 历史重评：开放窗口内迟到资料继续修正当前命中；封存后的证据、人工或规则变化另成版本。
- 原因区分：每次变化标记为 `evidence`、`manual`、`rule` 或 `seal`。
- 模型扩展：`HeuristicModel` 是确定性占位模型，可将分数附加到规则证据。

## 快速验证

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m antifraud.examples.demo
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
engine.withdraw_evidence_judgment(
    "evt-t1",
    withdrawn_at=260,
    reason="evidence verified",
)

# 同一交易叠加多条人工判断，各自独立撤回
engine.exclude_evidence(
    "evt-t1",
    "false positive review",
    operator="analyst-1",
    decided_at=255,
    kind=JudgmentKind.FALSE_POSITIVE,
    judgment_id="j-fp",
)
engine.exclude_evidence(
    "evt-t1",
    "rule exception granted",
    operator="analyst-2",
    decided_at=256,
    kind=JudgmentKind.RULE_EXCEPTION,
    judgment_id="j-ex",
)
# 只撤回误报判断；规则例外仍然生效，命中不会恢复
engine.withdraw_evidence_judgment("j-fp", withdrawn_at=260)

# 解释当前命中：原始事件、规则版本、参与生效的人工决定
for hit in engine.all_hits():
    explanation = engine.explain_hit(hit.hit_id)
    print(explanation["rule"], explanation["active_manual_judgments"])

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
