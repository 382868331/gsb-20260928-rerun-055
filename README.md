# 反欺诈规则研究平台（第一版）

这是一个仅处理**虚构交易和虚构身份关联**的 Python 时序规则研究原型，不接收、存储或推断真实账户数据。

## 能力

- 事件时间处理：使用 watermark 和宽限期修正尚未封存的窗口。
- 规则版本：`CrossIdentityFlowRule` 当前版本为 `cross_identity_linked_flow/1.0.0`。
- 事件来源：每个事件携带 `EventSource(system, record_id, topic, metadata)`。
- 命中证据：命中结果保留触发交易、身份关联、窗口、参数和规则说明。
- 乱序修正：后到但仍处于开放窗口内的交易或身份关联会重新计算命中。
- 撤销联动：`TransactionRetraction` 删除交易后，依赖它的未封存命中同步撤回。
- 封存保护：超过封存边界的迟到事件不会修改历史结果。
- 模型扩展：`ModelScore` 可与规则命中在 `DecisionEngine` 中合并，分数不会替代证据。

## 规则：短时间跨多个关联身份交易

`CrossIdentityFlowRule` 识别一个身份在配置窗口内，与多个事先存在身份关联的对手方发生交易。默认要求 1 小时内至少 2 个关联对手方，且命中中保存具体交易和关联事件。

仅有相似时间形态但不存在指定身份关联的样例不会命中，避免把正常、无关但速度相近的行为直接当成风险。

## 快速验证

```bash
python -m pytest -q
```

主要代码：

- `fraud_rules/models.py`：虚构事件、交易、身份关联和撤销事件。
- `fraud_rules/rules.py`：规则版本、证据结构和跨身份规则。
- `fraud_rules/engine.py`：watermark、乱序重算、撤回和封存状态机。
- `fraud_rules/decision.py`：规则证据与后续模型评分的合并接口。
- `tests/test_temporal_rules.py`：乱序、撤销、正常行为、封存和模型评分测试。
