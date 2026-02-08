# prefetch-file-server

用于发布 `strategy_cache.json` 的轻量文件下载服务（Rust + Axum）。

## 功能

- 通过 HTTP 下载指定文件（当前路由：`GET /`）。
- 基于 `token` 的简单鉴权。
- 文件名白名单校验与目录穿越防护。
- 文件流式下载（支持大文件）。
- 日志滚动（按大小切分，保留历史文件）。

## 目录约定

- 默认数据目录：`data/`
- 默认日志文件：`server.log`
- 推荐发布文件：`data/strategy_cache.json`

## 配置

复制并编辑配置：

```bash
cp config.example.toml config.toml
```

核心参数（`config.toml`）：

- `ip`：监听地址，默认 `0.0.0.0`
- `port`：监听端口，默认 `8080`
- `token`：下载口令（必填；若未设置会随机生成并打印到日志）
- `data_dir`：可下载文件目录，默认 `data`
- `log_file`：日志文件路径
- `log_max_size_mb`：单个日志文件最大大小（MB）
- `log_keep_files`：日志滚动保留数量

## 启动

```bash
cargo run --release -- --config config.toml
```

可用命令行参数覆盖配置，例如：

```bash
cargo run --release -- --config config.toml --port 9090
```

## 下载接口

请求格式：

```text
GET /?token=<TOKEN>&filename=<FILENAME>
```

示例：

```bash
curl -fL "http://127.0.0.1:8080/?token=xxx-xxx-xxx-xxx&filename=strategy_cache.json" -o strategy_cache.json
```

说明：

- `filename` 仅允许 `[A-Za-z0-9._-]`，禁止路径分隔符。
- 返回 `application/octet-stream`，并附带 `Content-Disposition` 下载头。

## 与父仓协作

- 父仓 `ash-mcp` 的夜间任务会生成 `prefetch-file-server/data/strategy_cache.json`。
- 本服务负责把该文件对外发布下载，不参与指标计算逻辑。
