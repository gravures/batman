# Batman

`Simple command line backup utility wrapping duplicity programm.`


## installation

Cloning the repo and bootstrapping batman:

```bash
git clone https://github.com/gravures/batman.git && cd batman

source ./bootstrap.sh && bootstrap
micromamba create --prefix batman --file conda-lock.yml
micromamba run --prefix batman uv pip install -r requirements.txt
```

## developping

```bash
uv tool install conda-lock
conda-lock lock -f pyproject.toml
```
