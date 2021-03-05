_uftrace () {
    local cur prev subcmds options uftrace_comp

    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD - 1]}

    COMPREPLY=()

    subcmds='record replay report live dump graph info recv script tui'
    options=$(uftrace -h | awk '$1 ~ /--[a-z]/ { split($1, r, "="); print r[1] } \
                                $2 ~ /--[a-z]/ { split($2, r, "="); print r[1] }')
    demangle='full simple no'
    sort_key='total self call avg min max'

    uftrace_comp="${subcmds} ${options}"

    case $prev in
	-d|--data|--diff|-L|--library-path)
	    # complete directory name
	    COMPREPLY=($(compgen -d -- "${cur}"))
	    ;;
	--demangle)
	    COMPREPLY=($(compgen -W "${demangle}" -- "${cur}"))
	    ;;
	-s|--sort)
	    COMPREPLY=($(compgen -W "${sort_key}" -- "${cur}"))
	    ;;
	*)
	    # complete subcommand, long option or (executable) filename
	    COMPREPLY=($(compgen -f -W "${uftrace_comp}" -- "${cur}"))
	    ;;
    esac
    return 0
}
complete -o filenames -F _uftrace uftrace
