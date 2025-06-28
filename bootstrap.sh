PREFIX=$(pwd)/.mamba
MAMBA_ROOT="$PREFIX"/conda

function advertise() {
  echo "$*" >&2
}

function which_shell() {
  local parent

  parent=$(ps -o comm $PPID | tail -1)
  # remove the leading dash that login shells have
  parent=${parent#-}

  case "$parent" in
  # shells supported by `micromamba shell init`
  bash | dash | fish | tcsh | xonsh | zsh)
    echo "$parent"
    ;;
  *)
    # use the login shell (basename of $SHELL) as a fallback
    echo posix
    ;;
  esac
}

function install_mamba() {
  local target platform arch

  case "$(uname)" in
  Linux)
    platform="linux"
    ;;
  Darwin)
    platform="osx"
    ;;
  *NT*)
    platform="win"
    ;;
  esac

  arch="$(uname -m)"
  case "$arch" in
  aarch64 | ppc64le | arm64) ;; # pass
  *)
    arch="64"
    ;;
  esac

  case "$platform-$arch" in
  linux-aarch64 | linux-ppc64le | linux-64 | osx-arm64 | osx-64 | win-64) ;; # pass
  *)
    advertise "Failed to detect your OS"
    return 1
    ;;
  esac

  target="https://github.com/mamba-org/micromamba-releases/releases/latest/download/micromamba-${platform}-${arch}"

  mkdir -p "$PREFIX"/bin
  mkdir -p "$MAMBA_ROOT"

  if curl "${target}" -o "$PREFIX"/bin/micromamba -fsSL --compressed; then
    chmod +x "$PREFIX"/bin/micromamba
    touch "$MAMBA_ROOT"/.condarc
    echo "channels:" | tee -a "$MAMBA_ROOT"/.condarc
    echo "  - conda-forge" | tee -a "$MAMBA_ROOT"/.condarc
    echo "  - nodefaults" | tee -a "$MAMBA_ROOT"/.condarc
    echo "" | tee -a "$MAMBA_ROOT"/.condarc
    echo "channel_priority: strict" | tee -a "$MAMBA_ROOT"/.condarc

    advertise "successfully installed micromamba..."
  else
    advertise "something goes wrong with micromamba download..."
    return 1
  fi
}

function bootstrap() {
  if ! command -V "$PREFIX/bin/micromamba" >/dev/null 2>&1; then
    if ! install_mamba; then
      advertise "failed installing micromamba"
      return 1
    fi
  fi

  export MAMBA_ROOT_PREFIX=$MAMBA_ROOT
  export MAMBA_EXE="$PREFIX"/bin/micromamba
  eval "$("$PREFIX"/bin/micromamba shell hook --shell "$(which_shell)" "$MAMBA_ROOT")"
}
