# 反欺诈规则研究平台（第一版）

本项目只处理显式标注的虚构交易和身份关联事件，不连接真实账户、支付渠道或生产数据。

## 能力

- 规则版本：每条规则携带 `rule_id` 和 `version`，证据保留完整规则版本。
- 事件来源：事件信封包含来源系统、生产者和来源元数据。
- 时序窗口：按固定时间窗口识别跨多个关联身份的异常交易模式。
- 乱序修正：窗口封存前，迟到事件会触发同一命中的重新计算和更新。
- 撤销传播：交易事件被撤销后，依赖该交易的命中会转为 `revoked`。
- 命中证据：保存身份、交易、身份关联以及具体触发事件，不只输出风险分。
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
```

## 决策状态

- `open`：当前有效且仍可被窗口内事件修正。
- `updated`：本次摄入导致尚未封存的证据变化。
- `revoked`：撤销或有效事件重算后，该命中不再成立。
- `sealed`：水位已超过窗口边界，结果作为不可变快照保留。
