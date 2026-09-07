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
    _nsg_command_log="${_nsg_history_dir}/commands-$(id -u)-${PPID}-$$.jsonl"
    _nsg_json_escape() {
        local value=$1
        value=${value//\\/\\\\}
        value=${value//\"/\\\"}
        value=${value//$'\n'/\\n}
        value=${value//$'\r'/\\r}
        value=${value//$'\t'/\\t}
        printf '%s' "$value"
    }
    _nsg_save_history() {
        local command_status=$?
        history -a
        local sequence=${HISTCMD:-0}
        if [[ "$sequence" != "${_nsg_last_history_sequence:-}" ]]; then
            local command_text
            command_text=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null || true)
            command_text=${command_text#${command_text%%[![:space:]]*}}
            command_text=${command_text#* }
            command_text=${command_text#${command_text%%[![:space:]]*}}
            if [[ -n "$command_text" ]]; then
                local escaped_command escaped_cwd escaped_tty tty_name
                tty_name=$(tty 2>/dev/null || true)
                escaped_command=$(_nsg_json_escape "$command_text")
                escaped_cwd=$(_nsg_json_escape "$PWD")
                escaped_tty=$(_nsg_json_escape "$tty_name")
                printf '{"ts":%s,"source":"bash-observer","event":"command_completed","uid":%s,"pid":%s,"ppid":%s,"cwd":"%s","tty":"%s","sequence":%s,"exit_status":%s,"command":"%s"}\n' \
                    "${EPOCHSECONDS}" "$(id -u)" "$$" "$PPID" "$escaped_cwd" "$escaped_tty" \
                    "$sequence" "$command_status" "$escaped_command" >> "$_nsg_command_log"
            fi
            _nsg_last_history_sequence=$sequence
        fi
        if [[ -n ${_nsg_previous_prompt_command} ]]; then
            eval "${_nsg_previous_prompt_command}"
        fi
    }
    PROMPT_COMMAND=_nsg_save_history
    unset _nsg_history_dir
fi
