# Sourced by interactive Bash shells to preserve commands with timestamps.
# This is supplementary to syscall and terminal recording.
if [[ $- == *i* ]] && [[ -n ${OBS_OUTPUT_DIR:-} ]]; then
    _nsg_history_dir="${OBS_OUTPUT_DIR}/tty"
    mkdir -p "${_nsg_history_dir}" 2>/dev/null || true
    HISTFILE="${_nsg_history_dir}/bash-history-$(id -u)-${PPID}-$$.log"
    HISTSIZE=-1
    HISTFILESIZE=-1
    HISTCONTROL=
    HISTIGNORE=
    HISTTIMEFORMAT='%s '
    shopt -s cmdhist lithist
    _nsg_previous_prompt_command="${PROMPT_COMMAND:-}"
    _nsg_save_history() {
        history -a
        if [[ -n ${_nsg_previous_prompt_command} ]]; then
            eval "${_nsg_previous_prompt_command}"
        fi
    }
    PROMPT_COMMAND=_nsg_save_history
    unset _nsg_history_dir
fi
