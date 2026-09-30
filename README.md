# 反欺诈规则研究平台（第二版）

本项目只处理显式标注的虚构交易和身份关联事件，不连接真实账户、支付渠道或生产数据。

## 能力

- 规则版本：每条规则携带 `rule_id` 和 `version`，证据保留完整规则版本。
- 事件来源：事件信封包含来源系统、生产者和来源元数据。
- 时序窗口：按固定时间窗口识别跨多个关联身份的异常交易模式。
- 乱序修正：窗口封存前，迟到事件会触发同一命中的重新计算和更新。
- 撤销传播：交易事件被撤销后，依赖该交易的命中会转为 `revoked`。
- 命中证据：保存身份、交易、身份关联以及具体触发事件，不只输出风险分。
- 模型扩展：`HeuristicModel` 是确定性占位模型，可将分数附加到规则证据。
- 人工证据排除：分析人员可否定某条身份关联或交易证据，原事件和原结论都不删除，命中带人工理由重算；撤回人工判断后恢复原计算。
- 规则修订重评：`revise_rule` 用新版本规则重评历史，开放窗口直接修正，封存窗口保留旧快照并另成版本。
- 变化归因：每次修订标注 `evidence`（迟到资料/撤销）、`manual`（人工排除/撤回）、`rule`（规则修订）或 `seal`（封存）。
- 修订谱系：同一决策线（规则 id + 窗口 + 身份组件）按 `revision` 串联，可通过 `hit_history` / `all_revisions` 追溯。

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
```

## 决策状态

- `open`：当前有效且仍可被窗口内事件修正。
- `updated`：本次摄入导致尚未封存的证据变化。
- `revoked`：撤销或有效事件重算后，该命中不再成立。
- `sealed`：水位已超过窗口边界，结果作为不可变快照保留。

## 人工复核与规则修订

```python
from antifraud.reviews import exclude_request, withdraw_request

# 否定证据：原事件保留在事件日志中，受影响命中重算并记录理由
engine.review_evidence(
    exclude_request(
        "evt-link-ab",
        reviewer="analyst-7",
        reason="身份关联被证实为数据合并错误",
        reviewed_at=240,
    )
)

# 撤回人工判断：事件重新参与计算，原命中作为新版本恢复
engine.review_evidence(
    withdraw_request("evt-link-ab", reviewer="lead-3", reason="申诉成立", reviewed_at=260)
)

# 规则修订：开放窗口内修正，封存窗口保留旧版本并追加新版本
engine.revise_rule(
    CrossIdentityFlowRule(
        rule_id="cross_identity_flow", version="v2",
        window_seconds=300, min_identities=3, min_total_amount=1500,
    ),
    revised_at=320,
)

for revision in engine.all_revisions():
    print(revision.revision, revision.status, revision.change_cause)
```

封存后到达的迟到资料不会覆盖封存快照，而是追加一条新的封存修订；`hit_history(line_key)` 返回该决策线的全部版本，每条修订通过 `supersedes_revision` 指向上一版。
