_uftrace() 
{
    local CMD=${COMP_WORDS[0]}
    local CUR=${COMP_WORDS[COMP_CWORD]}
    local PREV=${COMP_WORDS[COMP_CWORD - 1]}
    [[ $PREV = "=" ]] && PREV=${COMP_WORDS[COMP_CWORD-2]}
    local IFS=$' \t\n' WORDS OPTS=() OPT1=() OPT2=() TMP i
    local COMP_LINE2=${COMP_LINE:0:$COMP_POINT}
    [[ ${COMP_LINE2: -1} = " " && -n $CUR ]] && CUR=""

    IFS=$'\n'
    for TMP in $( $CMD --help | sed -En '/^\s+-/{ s/^\s{,10}((-\w),?\s)?(--[[:alnum:]-]+=?)?.*/ \2 \3/p }')
    do
        if [[ $TMP =~ "=" ]]; then 
            TMP=${TMP/=/} OPT1+=( ${TMP// /$'\n'} )
        else
            OPT2+=( ${TMP// /$'\n'} )
        fi
    done
    unset IFS

    OPTS=( "${OPT1[@]}" "${OPT2[@]}" )
    if [[ $CUR =~ ^-- ]]; then
        WORDS=${OPTS[@]/#-[^-]*/}
    elif [[ $CUR =~ ^- ]]; then
        WORDS=${OPTS[@]/#--*/}" -?"
    else
        if [[ $PREV = @(-d|--data|--diff|-L|--libmcount-path) ]]; then
	        COMPREPLY=( $(compgen -d -- "$CUR") )
            return
        elif [[ $PREV = --color ]]; then
            WORDS="yes no auto"
        elif [[ $PREV = --demangle ]]; then
            WORDS="full simple no"
        elif [[ $PREV = --match ]]; then
            WORDS="regex glob"
        elif [[ $PREV = @(-s|--sort) ]]; then
            WORDS="total self call avg min max"
        else
            WORDS="record replay live report info dump recv graph script tui"
            if printf '%s\n' "${OPT1[@]}" | grep -xq -- "$PREV" || 
                [[ $PREV = @(,|@) ]] || [[ $CUR = @(,|@) ]]; then
                WORDS=""
            else
                for (( i = 1; i < ${#COMP_WORDS[@]}; i++ )); do
                    for TMP in $WORDS; do
                        [[ ${COMP_WORDS[i]} = $TMP ]] && WORDS=""
                    done
                done
            fi
        fi
    fi
    [[ $CUR = "=" ]] && CUR=""
    COMPREPLY=( $(compgen -W "$WORDS" -- "$CUR") )
    [ "${COMPREPLY: -1}" = "=" ] && compopt -o nospace
}

complete -o default -o bashdefault -F _uftrace uftrace

