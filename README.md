# StudyVault

Um cofre para o que você estuda. Tópicos, notas em **Markdown** com realce de código, **tags**, **busca** e imagens anexadas.

Feito com Flask. Roda com SQLite no seu computador e com Postgres + Supabase Storage em produção, tudo no plano gratuito.

## Revisão espaçada

Toda nota entra na revisão no dia seguinte ao que foi escrita. Na revisão, você vê só o título, tenta lembrar, revela a nota e responde:

| Resposta | O que acontece |
|---|---|
| **Esqueci** | volta amanhã e a nota fica marcada como mais difícil |
| **Com esforço** | o intervalo cresce devagar |
| **Lembrei** | o intervalo cresce cada vez mais (3 dias, 7 dias, ~18 dias…) |

O algoritmo é um SM-2 simplificado (`review.py`), o mesmo princípio do Anki. "Hoje" segue o fuso do navegador. Dá para revisar o cofre inteiro ou só um tópico, e o app mostra a sequência de dias seguidos.

Atalhos na revisão: `espaço` revela, `1` `2` `3` respondem.

## Design

- **Sensação:** um cofre silencioso. Quase preto azulado, uma única cor de destaque (azul-gelo) usada só para foco, seleção e progresso.
- **Tipografia:** Newsreader para ler, Geist para a interface e Geist Mono para metadados e para escrever. O texto cru é escrito em mono e lido em serifa.
- **Composição:** índice de tópicos como sumário de livro, notas em lista editorial e leitura em coluna de ~66 caracteres. Sem cards.
- **Movimento:** o dial da entrada gira uma vez, como uma combinação sendo aberta. Os elementos entram em sequência, o título da nota faz transição entre a lista e a leitura (View Transitions) e uma linha de progresso acompanha a leitura. Tudo desliga com `prefers-reduced-motion`.
- **Mobile:** o índice vira uma folha de tela cheia, e as linhas de nota se reorganizam em vez de encolher.
- **Atalhos:** `/` busca, `Ctrl/⌘ S` guarda a nota, `Esc` fecha o índice. Na revisão, `espaço` revela e `1` `2` `3` respondem.

## Rodar localmente

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Acesse: http://127.0.0.1:5000

Sem nenhuma configuração, o banco fica em `instance/studyvault.db` e as imagens em `instance/uploads/`.

## Deploy gratuito (Render + Supabase)

No Render, os arquivos do servidor são apagados a cada deploy. Por isso, banco e imagens ficam no Supabase.

1. Crie um projeto grátis em [supabase.com](https://supabase.com).
2. Em **Project Settings → Database → Connection string**, copie a URL do **Session pooler**. Ela funciona via IPv4, que é o que o Render usa.
3. Em **Project Settings → API**, copie a **Project URL** e a chave **service_role**.
4. No Render, em **Environment**, configure:

| Variável | Valor |
|---|---|
| `SECRET_KEY` | resultado de `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | URL do Session pooler (com a senha do banco) |
| `SUPABASE_URL` | Project URL |
| `SUPABASE_SERVICE_KEY` | chave service_role (nunca exponha no front) |

5. Comando de start: `gunicorn app:app`

As tabelas e o bucket privado `studyvault` são criados automaticamente na primeira subida.

> O plano gratuito do Supabase pausa o projeto após 7 dias sem uso. Basta reativar no painel.

## Busca
- **Texto:** digite qualquer termo. A busca olha título, conteúdo e tags.
- **Tag:** use `tag:sql` ou clique em uma tag. O match é exato, então `tag:sql` não encontra `mysql`.

## Segurança
- Senhas com hash (Werkzeug).
- Proteção CSRF em todos os formulários.
- HTML do Markdown sanitizado (nh3).
- Imagens em armazenamento privado, entregues só para o dono da nota.
- O app não sobe em produção sem `SECRET_KEY`.
