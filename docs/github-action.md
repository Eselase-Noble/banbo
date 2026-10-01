# GitHub Action

Run banbo in any repository's CI. The job's exit code gates the build (`0` clean, `1` low/medium, `2` high/critical).

```yaml
name: security
on: [push, pull_request]
jobs:
  banbo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Eselase-Noble/banbo@v1
        with:
          args: "code ."
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}   # optional, enables AI review
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `args` | `code .` | Arguments passed to banbo, e.g. `"code . --full"` or `"scan example.com.gh -y"` |
| `version` | `latest` | banbo image tag to run (e.g. `v0.1.3`) |

## Notes

- The action runs on **Linux runners** (it uses the published Docker image).
- The checked-out repository is mounted at `/src`; `code .`/`advise .` audit it directly.
- `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` set on the step are forwarded to banbo.
- Pin `@v0.1.3` instead of `@v1` if you want an immutable reference.
