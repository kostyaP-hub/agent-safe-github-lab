# Первичные источники и что из них взято

- [GitHub: secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) — пинning third-party Actions по полному commit SHA и принцип минимальных token permissions.
- [GitHub: compromised runners](https://docs.github.com/en/actions/concepts/security/compromised-runners) — job может выполнять произвольные команды и передавать данные по HTTP; нужен минимальный доступ к `GITHUB_TOKEN`.
- [npm install](https://docs.npmjs.com/cli/v11/commands/npm-install/) — lifecycle scripts включают `preinstall`, `install`, `postinstall` и `prepare`.
- [OWASP: prompt injection](https://genai.owasp.org/llmrisk2023-24/llm01-24-prompt-injection/) — непрямая инъекция во внешнем контенте может приводить к злоупотреблению инструментами и эксфильтрации.
- [GitHub: immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) — неизменяемые релизы и attestations снижают риск подмены после проверки.
- [SLSA: verifying artifacts](https://slsa.dev/spec/v1.0-rc1/verifying-artifacts) — ожидаемое отсутствие provenance должно быть причиной отказа, а не молчаливого продолжения.

Дата сверки: 2026-09-17. Ссылки объясняют принципы; учебный сканер не является
реализацией всех их требований.
