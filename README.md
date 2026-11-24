# 证据出库的代理冲突与最小独立证明

获确认的题面位于 `task/PROMPT.txt`。本仓使用 **Windows + Python 3.12 标准库**实现本地合成审计，不依赖第三方包或外部服务。

## 运行

```powershell
py -3.12 run_audit.py
# 或
python run_audit.py
```

等价入口：

```powershell
python -m forensic_audit
```

测试与全部独立核对：

```powershell
python -m unittest discover -s tests -v
```

CLI 会：

1. 重放合成取证仓的提交事件；
2. 对 **0 号及每个生效水位**输出每个“案件 × 证据”目标的最小签核证明或不可出库理由；
3. 运行两线程、屏障、本地故障注入和撤销抢先检查；
4. 用独立小模型枚举 **12,288 组审查人/根授权/撤销/成本组合**和 **30 种短交错**；
5. 生成 **50,000 条代理路径**，撤销一个指定授权后只重算相关案件，并与全量重算逐条核对；
6. 写出 `artifacts/audit_report.json`，并发场景的 JSONL 提交日志位于 `artifacts/concurrency/`。

`artifacts/` 已在 `.gitignore` 中忽略；测试会在临时目录中重复验证报告生成。

最近一次本地验证：`10/10 unittest checks OK`，CLI 汇总为 `ok: true`。

## 出库规则

一次出库必须同时满足：

- **证据属于请求案件**：共享证据不会把 A 案件的根授权或签核带到 B 案件；
- **证据代一致**：签核绑定提交时的 `generation`，证据换代后旧签核变为 `STALE_GENERATION`；
- **恰好两个独立席位**：必须有两个不同签核、不同审查人、不同根授权、不同底层控制人；
- **代理链有效**：临时代理可以多跳，但每一跳必须连接到本案的有效根授权，撤销、跨案授权或环都不能形成证明；
- **禁止同根凑两席**：两个审查人即使都能签，只要回溯到同一个 `root_authorization_id` 或同一个底层控制人，就不能组成有效证明；
- **最小证明**：枚举所有可用“签核 → 根”席位，按 `(总成本, 代理跳数, 签核 ID, 根 ID)` 选择确定性的最小组合。

水位是只增的提交序列号。撤销或换代只影响该事件及之后的水位；旧水位的决定和证明保持不变，因此可以区分：

- **已承诺**：签核事件已写入 fsynced JSONL 并获得水位，即使提交后注入故障，恢复重放仍存在；
- **撤销抢先**：撤销先获得水位，签核线程在屏障后重新校验失败，只写 `SignoffRejected` 审计记录，不产生签核席位；
- **换代抢先**：证据换代先提交，旧代签核被拒绝；若签核先提交，则该旧水位仍可证明，新水位才因换代失效。

## 代码地图

| 文件 | 内容 |
|---|---|
| `forensic_audit/engine.py` | 事件模型、水位重放、案件隔离、多跳代理链、同根冲突、最小双席位证明、理由码和合成主场景 |
| `forensic_audit/storage.py` | 标准库 JSONL/fsync 提交日志、恢复重放、本地故障注入点 |
| `forensic_audit/concurrency.py` | 签核线程、证据换生产线程、`threading.Barrier`/事件门、承诺与抢先场景 |
| `forensic_audit/small_model.py` | 独立暴力枚举审查人组合、根选择和 30 种短交错的小模型 |
| `forensic_audit/scale.py` | 50,000 条代理路径、案件/授权索引、增量重算和全量逐条比对 |
| `forensic_audit/cli.py` | 一键核对、不变量断言和完整 JSON 报告 |
| `tests/test_audit.py` | 核心、并发、小模型、5 万路径和 CLI 的 `unittest` 覆盖 |

## 报告中的关键合成场景

`EV-SHARED` 同时属于 `CASE-ALPHA` 和 `CASE-BETA`：

- Mayer 控制人经 `Mayer → Dalton → Reyes` 两跳代理；
- Okafor 直接授权 Ito，同时经 `Okafor → Voss → Chen/Patel` 扇出；
- Chen 和 Patel 很便宜，但共享 `ROOT-OKAFOR`，不能凑成两个独立席位；
- Park 授权 Sato，形成第三个独立根；
- 撤销 `G-OKAFOR-VOSS` 后，Chen/Patel 同时失效，但 Ito 的另一条直接授权仍有效，因此枚举出成本更小的 `Ito + Sato` 独立见证，而不是机械使用昂贵的 `Reyes + Sato` 替代；
- `CASE-BETA` 没有本案根授权，即使证据共享且存在 B 案签核，也不能出库；
- `EV-SHARED` 换代到 2 后，所有一代签核失效，直到二代独立签核提交。

5 万路径检查指定撤销 `HUB-C-025-1`：影响 125 条路径，相关案件仅 `C-025`，增量器重算该案件的 500 条路径；随后与全量重算比较 50,000 条路径结果和 100 个案件证明，全部相等。
