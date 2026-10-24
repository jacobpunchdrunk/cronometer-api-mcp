# Cloudflare Container image for the Cronometer MCP (see DEPLOY.md).
# Runs the native streamable-HTTP transport, so the built-in OAuth
# approve-secret gate is always on. The repo-root Dockerfile (supergateway,
# stdio, no auth) is NOT used for hosting.
FROM python:3.14-slim
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev && useradd -r -u 10001 app && chown -R app /app
USER app
ENV PATH="/app/.venv/bin:$PATH" MCP_TRANSPORT=streamable-http PORT=8080
EXPOSE 8080
CMD ["cronometer-api-mcp"]
