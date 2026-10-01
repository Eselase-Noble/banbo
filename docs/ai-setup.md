# AI setup

banbo's AI features are **bring-your-own-key** — you supply a Claude or OpenAI key; banbo never ships one. **Claude is preferred; OpenAI is the fallback.** Without a key, `scan` and `code` still work using built-in heuristics and static pattern rules (no AI explanations); `advise` requires a key.

## Set a key

=== "Environment"

    ```bash
    export BANBO_API_KEY=sk-ant-...      # Claude   (or ANTHROPIC_API_KEY)
    export OPENAI_API_KEY=sk-...         # OpenAI   (or BANBO_OPENAI_API_KEY)
    ```

=== "Config file"

    Create `~/.banbo/config.json`:

    ```json
    {
      "api_key": "sk-ant-...",
      "model": "claude-opus-4-8",
      "openai_api_key": "sk-...",
      "openai_model": "gpt-4o-mini"
    }
    ```

Run `banbo config` to see which provider is active.

!!! danger "Never commit your key"
    Keys are read only from the environment or `~/.banbo/config.json` (both gitignored). Do not put a key in source, a Dockerfile, or CI logs. In CI, pass it as a secret (e.g. `ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}`).

## Model overrides

- Claude model: `BANBO_MODEL` (default `claude-opus-4-8`).
- OpenAI model: `OPENAI_MODEL` / `BANBO_OPENAI_MODEL` (default `gpt-4o-mini`).

## Selection logic

1. If a Claude key is set → use Claude (fall back to OpenAI on a transient failure when both are set).
2. Else if an OpenAI key is set → use OpenAI.
3. Else → built-in guidance (`scan`/`code`), or an error for `advise`.
