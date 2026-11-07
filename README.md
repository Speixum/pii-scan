# pii-scan

零依赖的敏感信息（PII）扫描与脱敏工具：识别中文身份证、银行卡、手机号、邮箱、
统一社会信用代码与 IPv4，给出高/中/低三档置信度，并支持掩码、哈希、删除三种脱敏。

- **纯标准库**：`dependencies = []`，不装第三方包，离线可跑。
- **先校验、再定级**：身份证走 GB 11643 模 11 校验位，银行卡走 Luhn，校验不过不会报 high。
- **流式处理**：大文件按块扫描，内存占用只跟块大小有关（默认 1 MB）。
- **报告只含掩码**：表格、JSON、单文件 HTML 三种输出都只打印 `preview`，不会把原文写进报告。

## 它解决什么问题

给数据集/日志/工单做入库前的体检：哪些文件里躺着身份证号、手机号、卡号？
命中的是"真值"还是"看起来像"？批量脱敏后原文件还能不能保持结构？

pii-scan 把这件事拆成三步：

1. **发现**：正则找候选，再用校验器（模 11、Luhn、号段、域名）打分；
2. **定级**：分数映射成 `high/medium/low`，再映射成 `high_sensitive/sensitive/general`，
   低置信的命中自动降级，避免"18 位数字就是身份证"的误报；
3. **处置**：按级别或自定义策略做 `mask`（保留首尾）、`hash`（sha256+盐）、`redact`（等长星号或删除）。

## 快速开始

```bash
# 1. 生成全是假数据、校验位正确的样本（不碰任何真实数据）
python scripts/gen_fake.py

# 2. 扫描，控制台表格
python -m piiscan scan data/sample.txt

# 3. 扫描，写 JSON 报告
python -m piiscan scan data/sample.txt --format json -o data/sample.json

# 4. 扫描，写单文件 HTML 报告（断网可看）
python -m piiscan scan data/sample.txt --format html -o data/sample.html

# 5. 脱敏：整份文件按策略替换
python -m piiscan mask data/sample.txt -o data/sample.masked.txt --strategy hash --salt demo

# 6. 只演练不落盘
python -m piiscan mask data/sample.txt --dry-run
```

不需要安装：仓库根目录下直接 `python -m piiscan ...` 即可。
想用 `piiscan` 这个短命令，再执行 `pip install -e .`（只注册入口点，仍然零运行期依赖）。

## 命令参考

```text
piiscan scan  <file|-> [--format table|json|html] [-o PATH]
                      [--min-confidence low|medium|high] [--fail-on none|medium|high]
                      [--type TYPE ...] [--rules PATH] [--chunk-size N] [--overlap N]
piiscan mask  <file> [-o PATH] [--in-place] [--action|--strategy mask|hash|redact]
                      [--policy PATH] [--head N] [--tail N] [--salt TEXT]
                      [--keep-prefix N] [--redact-mode stars|remove] [--dry-run]
piiscan rules list  [--rules PATH] [--format table|json]
piiscan rules check [--rules PATH]
```

- `scan -` 从 stdin 读，适合接管道：`type notes.txt | python -m piiscan scan - --format json`。
- `--type cn_id_card --type bank_card` 只扫指定类型（可重复）。
- `mask` 默认输出 `<name>.masked<ext>`；写回原文件必须显式 `--in-place`。
- `--head 3 --tail 4` 控制掩码保留的首尾字符数；`--keep-prefix` 只作用于 hash。

### 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功（未达到 `--fail-on` 阈值） |
| 1 | 参数、IO 或规则文件错误 |
| 2 | 有命中达到 `--fail-on` 的置信度（CI 用） |

## 输出格式

### JSON（schema `pii-hits/1.0`）

```json
{
  "schema": "pii-hits/1.0",
  "source": "data/sample.txt",
  "generated_at": "2026-11-08T01:40:00Z",
  "findings": [
    {
      "type": "cn_id_card",
      "level": "high_sensitive",
      "confidence": "high",
      "score": 0.85,
      "offset": 90,
      "end": 108,
      "line": 4,
      "col": 13,
      "length": 18,
      "preview": "4403**********0508",
      "checksum": true,
      "reasons": ["regex:cn_id_card", "checksum:mod11"]
    }
  ],
  "summary": {
    "total": 1,
    "by_type": { "cn_id_card": 1 },
    "by_confidence": { "low": 0, "medium": 0, "high": 1 },
    "by_level": { "general": 0, "sensitive": 0, "high_sensitive": 1 },
    "by_action": { "mask": 1 }
  },
  "ruleset": { "name": "builtin", "version": "1.0", "file": null }
}
```

- `offset/end` 是**字符**坐标（不是字节），`line/col` 从 1 开始，`col` 按字符计。
- `checksum` 只在规则带校验器时有意义：`true` 通过、`false` 不通过、`null` 不适用。
- `preview` 已按规则掩码，报告里永远不会出现原值。

### 表格

ASCII 边框 + 中文双列宽对齐，Windows 控制台（GBK）也不会抛 `UnicodeEncodeError`。

### HTML

单个 `.html` 文件，CSS 内联、无脚本、无 CDN、无字体外链，断网双击可看；
页面里的号码全部是 `preview`。

## 检测与定级

分数 = 规则基础分 + 校验通过奖励（+0.30）或失败惩罚（-0.25）+ 上下文关键词（+0.15），最后钳制到 0..1。

| 分数 | 置信度 | 定级 |
| --- | --- | --- |
| >= 0.75 | high | 用规则声明的级别 |
| >= 0.45 | medium | 在规则级别上降一档 |
| < 0.45 | low | 一律 `general` |

内置 6 条规则：

| 规则 | 校验 | 基础分 | 声明级别 |
| --- | --- | --- | --- |
| `cn_id_card` | 18 位 + 模 11 校验位 | 0.55 | high_sensitive |
| `bank_card` | 16-19 位 + Luhn | 0.50 | high_sensitive |
| `mobile_cn` | 1[3-9] 号段 + 11 位 | 0.50 | sensitive |
| `email` | 本地部分@域名 | 0.50 | sensitive |
| `uscc` | 18 位统一社会信用代码字符集 | 0.50 | sensitive |
| `ipv4` | 四段点分十进制 | 0.40 | general |

所以：身份证校验通过 = 0.55+0.30 = 0.85 → high；校验失败 = 0.30 → low；
校验失败但旁边写着"身份证" = 0.45 → medium。不会出现"正则命中就 high"。

## 自定义规则

`--rules` 接受 JSON 或 TOML，示例见 `examples/custom_rules.json`：

```json
{
  "schema": "pii-rules/1.0",
  "name": "demo-custom",
  "version": "1.0",
  "rules": [
    {
      "name": "employee_id",
      "type": "employee_id",
      "regex": "(?<![A-Za-z0-9-])EMP-[0-9]{6}(?![A-Za-z0-9-])",
      "validators": [],
      "context_keywords": ["员工编号", "工号", "employee"],
      "weight": 0.6,
      "level": "sensitive",
      "preview": "head3_tail4"
    }
  ]
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `name` | 是 | 规则名，唯一；写进 `reasons` 的 `regex:<name>` |
| `type` | 是 | 命中类型，如 `cn_id_card` |
| `regex` | 是 | 必须可编译、不得匹配空串、长度 <= 500 |
| `validators` | 否 | 校验器名：`cn_id_card`、`luhn`、`mobile_cn`、`email`、`uscc`、`ipv4` |
| `context_keywords` | 否 | 命中前后 20 字符窗口内的关键词 |
| `weight` | 否 | 基础分 0..1，默认 0.5 |
| `level` | 否 | `high_sensitive|sensitive|general`，默认 `sensitive` |
| `preview` | 否 | `head4_tail4|head3_tail4|head1_tail1|star_all|email|ipv4`，默认 `head3_tail4` |

未知字段、重复规则名、非法正则都会在 `rules check` 阶段直接报错，不会带病运行。
TOML 规则文件依赖 Python 3.11+ 的 `tomllib`；JSON 规则无此限制。

## 脱敏

| 动作 | 效果 | 默认用于 |
| --- | --- | --- |
| `mask` | 保留首 3 尾 4，中间等长星号 | high_sensitive / sensitive |
| `hash` | `sha256:<64 hex>`，可加盐、可留前缀 | general |
| `redact` | 等长星号（`stars`）或直接删掉（`remove`） | 手动指定 |

- 策略文件是 `{"类型": "动作"}` 的 JSON，`"*"` 是兜底：
  ```json
  { "*": "hash", "cn_id_card": "mask" }
  ```
- 优先级：`--policy` 里的类型 > `--policy` 的 `"*"` > 级别默认动作；`--strategy` 会覆盖整个策略。
- 只替换命中的字符区间，换行、BOM、文件其余字节原样保留（`utf-8 + surrogateescape` 编解码）。
- 同一次运行里重叠区间只替换第一个，其余计入 `skipped`。

## 流式处理

`scan` 和 `mask` 都把文件按 `--chunk-size`（默认 1 MB 字符）分块读取，块间保留
`--overlap`（默认 512，最小 64）字符的重叠，跨块的命中不会被切断；
重叠产生的重复命中按 `(规则, offset, end)` 去重。

100 MB 文本的常驻内存大致是"一个块 + 命中列表"，不会把整个文件读进内存。

## 目录结构

```text
pii-scan/
├─ piiscan/
│  ├─ scanner.py      # 分块扫描、重叠去重、上下文加权、定级
│  ├─ rules.py        # 规则加载与校验（内置 + 自定义 JSON/TOML）
│  ├─ rules/builtin.json
│  ├─ validators.py   # 模 11、Luhn、号段、邮箱、USCC、IPv4
│  ├─ classify.py     # 分数 -> 置信度 -> 级别 -> 建议动作
│  ├─ mask.py         # mask/hash/redact + 文件级脱敏
│  ├─ report.py       # 表格 / JSON / 单文件 HTML
│  └─ cli.py          # 命令行入口
├─ scripts/gen_fake.py  # 生成校验位正确的假样本
├─ examples/custom_rules.json
├─ data/sample.txt      # 生成物（可重新生成）
└─ tests/               # unittest，标准库跑
```

## 测试

```bash
python -m unittest discover -s tests -v
```

覆盖：校验器边界（校验位、Luhn、号段）、分块与跨块命中、重叠去重、
定级与降级、三种脱敏动作、策略优先级、报告契约（JSON/HTML 无外链）、CLI 退出码与参数别名。

## 边界（这个工具不做什么）

- 只处理**纯文本**：不做 OCR、不解析 docx/xlsx/pdf；
- 不内置中文姓名/地址规则：这两类靠上下文极易误报，需要时请用自定义规则加；
- 不保证 100% 召回：PII 检测本质是启发式，报告用于"发现问题"，不能当合规审计结论；
- 不联网、不写用户没指定的路径、不把原文写进日志或报告。

## License

MIT，见 [LICENSE](LICENSE)。
