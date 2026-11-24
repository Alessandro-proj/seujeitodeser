# Seu jeito de ser

Teste de temperamentos da Natalia Nunes. A pessoa marca as frases com que se identifica, informa o nome e assina na tela. O painel reúne os envios para a Natalia consultar e preparar a devolutiva.

## Demonstração local

Com Python 3.10 ou mais recente, execute este comando na raiz do repositório.

```sh
python app/servidor-local.py
```

- [Abrir o teste](http://127.0.0.1:8765/)
- [Abrir o painel](http://127.0.0.1:8765/admin)

No primeiro acesso ao painel, copie o código de `work/painel-local/configuracao.txt` e escolha uma senha com pelo menos 12 caracteres. O código é descartado depois da configuração.

Enquanto o servidor estiver rodando, os novos envios aparecem no painel com nome, data, frases marcadas e assinatura. Para experimentar o fluxo, envie uma resposta fictícia.

## Armazenamento

O servidor usa SQLite e cria o banco em `work/painel-local/respostas.sqlite3`. Essa pasta é local e está no `.gitignore`. O formulário e o painel são servidos em `127.0.0.1` para demonstração neste computador.
