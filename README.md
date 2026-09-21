# SubPilot 规则集 / Rule sets

由 GitHub Actions 获取来源、合并、去重并分桶。产物分支固定为 rules。

GitHub Actions fetches sources, merges and deduplicates rules, and splits them into client-specific buckets on the fixed rules branch.

- Surge/: Surge 文本规则 / text rule sets
- Clash/: Clash YAML 规则 / YAML rule providers
- Sing-Box/: sing-box SRS 二进制规则 / binary rule sets

每个客户端目录内按规则集名称分类，仅生成所需文件。manifest.json 是发布校验信息。

Each client directory contains named rule-set folders with only the required files. manifest.json is the publication receipt.
