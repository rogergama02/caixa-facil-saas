# CaixaFácil — SaaS (backend + frontend pronto)

Este pacote contém:
- Backend Node.js/Express com SQLite (multi-tenant por usuário)
- Autenticação (JWT via cookie)
- Fluxo de cadastro → pagamento (Stripe Checkout) → liberação
- Páginas estáticas: login, cadastro, pagamento, dashboard e index (lançamentos)
- API REST `/api/tx` com escopo por usuário

## 1) Como rodar localmente

```bash
# 1. Node 18+
node -v

# 2. Instalar dependências
npm i

# 3. Copiar variáveis
cp .env.example .env
# (em desenvolvimento, pode deixar STRIPE_* vazio: a assinatura é ativada automaticamente)

# 4. Iniciar
npm start
# abre em http://localhost:3000
```

## 2) Configurar Stripe (opcional, para produção)

1. Crie um **Product** e um **Price** (recorrente) no Stripe.
2. Preencha no `.env`: `STRIPE_SECRET_KEY` e `STRIPE_PRICE_ID`.
3. Para testar webhooks localmente:
   ```bash
   stripe listen --forward-to localhost:3000/webhook
   ```
   Copie o `Signing secret` para `STRIPE_WEBHOOK_SECRET`.

Sem Stripe configurado, o `/api/checkout` ativa a assinatura automaticamente (modo dev).

## 3) Estrutura

```
server.js
public/
  login.html
  register.html
  payment.html
  payment-success.html
  payment-cancel.html
  index.html       (seus lançamentos, adaptado p/ API)
  dashboard.html   (seu dashboard, adaptado p/ API)
data/caixafacil.db (criado automaticamente)
```

## 4) Implantação

- **Render, Railway, Fly.io, VPS**: suba o repositório, configure as variáveis `.env` e rode `npm start`.
- **Banco**: SQLite em arquivo (persistente). Para ambientes com filesystem efêmero, use volume persistente.

## 5) Testar o fluxo

1. Abra `http://localhost:3000` → Login.
2. Se tentar logar com um e-mail não cadastrado, será levado ao **cadastro** automaticamente.
3. Após **cadastro**, você verá a página de **pagamento**.
   - Sem Stripe configurado: clique “Ativar no modo DEV” para liberar o acesso.
   - Com Stripe: clique em “Assinar agora” → Checkout. Ao retornar, faça login.
4. Acesse **Index** e **Dashboard** normalmente. Os dados ficam **separados por usuário**.
