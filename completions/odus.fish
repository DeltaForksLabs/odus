function __odus_print_remaining_args
    set -l tokens (commandline -opc) (commandline -ct)
    set -e tokens[1]
    argparse -s h/help -- $tokens 2>/dev/null

    if test -n "$argv"; and not string match -qr '^-' $argv[1]
        string join0 -- $argv
        return 0
    end

    return 1
end

function __odus_no_subcommand
    not __odus_print_remaining_args >/dev/null
end

function __odus_complete_subcommand
    set -l tokens (__odus_print_remaining_args | string split0)
    set -lx -a PATH /sbin /usr/sbin /usr/local/sbin
    __fish_complete_subcommand --commandline $tokens
end

complete -c odus -f
complete -c odus -n __odus_no_subcommand -s h -l help -d "Show help and version information"
complete -c odus -x -a "(__odus_complete_subcommand)"
