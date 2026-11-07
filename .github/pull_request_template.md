## 🎯 Objetivo deste Pull Request

Descreva o escopo técnico desta entrega e como ela contribui para a segurança LGPD/GDPR, deduplicação de incidentes ou diagnóstico de causa raiz.

---

## 🔒 Checklist de Governança & Segurança (LGPD + Zero-Leak Policy)

- [ ] **Zero-Leak Policy:** Confirmei via `git status` e `git diff` que nenhum arquivo `.env` ou chave real (`GEMINI_API_KEY`, tokens de Slack/Discord) entrou no stage.
- [ ] **Conformidade LGPD/GDPR (`LgpdPiiScrubber`):** Nenhum dado sensível (CPF, CNPJ, Cartão, Senha, JWT) pode ser persistido ou enviado para APIs externas sem antes passar pelo scrubber.
- [ ] **Análise Estática:** `composer analyse` (PHPStan Level 8) executa sem erros.
- [ ] **Testes Unitários:** `composer test` (PHPUnit 10.5) passa 100% dos cenários.
