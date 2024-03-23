# batman

`Personnal backup command line utility using duplicity.`


```bash
pipx install conda-lock
conda-lock lock -f pyproject.toml
micromamba create --always-copy --prefix ./.env --file conda-lock.yml
micromamba run -p ./.env pip install -r requirements.txt
```
