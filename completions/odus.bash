_odus() {
    local cur prev words cword split
    _init_completion -s || return

    local i
    for ((i = 1; i <= cword; i++)); do
        if [[ ${words[i]} != -* ]]; then
            local PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
            local root_command=${words[i]}
            _command_offset $i
            return
        fi
    done

    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W '--help' -- "$cur"))
        return
    fi

    $split && return

    local PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
    COMPREPLY=($(compgen -c -- "$cur"))
}
complete -F _odus odus
