#compdef stash

# zsh completion for stash (generated via go-flags)
_stash() {
    local IFS=$'\n'
    local -a completions
    completions=($(GO_FLAGS_COMPLETION=1 "${words[1]}" "${(@)words[2,$CURRENT]}" 2>/dev/null))
    if (( ${#completions} )); then
        compadd -- "${completions[@]}"
    else
        _files
    fi
}

_stash "$@"
