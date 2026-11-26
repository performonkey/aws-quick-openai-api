# aws-quick

将 **AWS Quick** 代理为标准 **OpenAI Compatible API** 的本地服务（基于 Node.js 内置标准库，无需额外安装依赖）。

## 功能特性

- **标准 OpenAI 接口**：提供 `/v1/models` 与 `/v1/chat/completions` 接口，支持流式输出（`stream`）、思考内容（`reasoning_content`）与工具调用（`tools`）。
- **多模型档位**：支持 `quick-fast`、`quick-balanced`、`quick-smart`。
- **浏览器登录与自动续期**：通过浏览器登录获取凭证并保存在 `./creds.json`，运行期间自动刷新凭证。
- **多轮对话与会话保持**：支持多会话并发与上下文隔离；会话记录自动保存到 `./sessions.json`，服务重启后自动恢复。

## 环境要求

- **Node.js >= 22.12.0**

## 使用方法

### 1. 登录并保存凭证

```bash
node aws-quick-openai-api.mjs creds
```

按终端提示操作：
1. 在浏览器中打开终端输出的登录链接完成登录。
2. 登录成功后打开浏览器 DevTools -> **Network** 面板，选中发往 `quick.aws.com/sn/account/...` 或 `quicksight.aws.amazon.com/sn/account/...` 的请求，复制 **Request Headers** 中完整的 **`cookie:`** 值。
3. 粘贴回终端并按回车确认，凭证会自动保存到 `./creds.json`。

如需重新登录，可运行：

```bash
node aws-quick-openai-api.mjs creds --relogin
```

### 2. 启动本地代理服务

```bash
node aws-quick-openai-api.mjs serve --port 8080
```

常用启动参数：
- `--host <host>`：监听地址（默认 `127.0.0.1`）
- `--port <port>`：监听端口（默认 `8080`）
- `--creds-file <path>`：指定凭证文件路径（默认 `./creds.json`）
- `--sessions-file <path>`：指定会话保存文件路径（默认 `./sessions.json`）
- `--api-key <key>`：可选，设置接口访问密钥（Bearer Token）
- `--debug`：开启调试日志

### 3. 调用示例

查看模型列表：

```bash
curl http://127.0.0.1:8080/v1/models
```

发送对话请求：

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "quick-smart",
    "messages": [
      {"role": "user", "content": "你好"}
    ]
  }'
```

在支持 OpenAI 接口的客户端（如 Claude Code、Cursor、Continue、Open WebUI 等）中，将 **Base URL** 设为 `http://127.0.0.1:8080/v1`，模型填写 `quick-smart`、`quick-balanced` 或 `quick-fast` 即可使用。
