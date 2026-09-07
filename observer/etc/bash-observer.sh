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
    _nsg_uid=$(id -u)
    _nsg_tty=$(tty 2>/dev/null || true)
    _nsg_command_log="${_nsg_history_dir}/commands-${_nsg_uid}-${PPID}-$$.jsonl"
    _nsg_json_escape() {
        local value=$1
        value=${value//\\/\\\\}
        value=${value//\"/\\\"}
        value=${value//$'\n'/\\n}
        value=${value//$'\r'/\\r}
        value=${value//$'\t'/\\t}
        printf '%s' "$value"
    }
    _nsg_current_command() {
        local value
        value=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null || true)
        value=${value#${value%%[![:space:]]*}}
        value=${value#* }
        value=${value#${value%%[![:space:]]*}}
        printf '%s' "$value"
    }
    _nsg_log_action_start() {
        local sequence=${HISTCMD:-0}
        local command_text action_id escaped_command escaped_cwd escaped_tty
        command_text=$(_nsg_current_command)
        [[ -n "$command_text" ]] || return 0
        action_id="bash:${HOSTNAME:-container}:$$:${sequence}"
        escaped_command=$(_nsg_json_escape "$command_text")
        escaped_cwd=$(_nsg_json_escape "$PWD")
        escaped_tty=$(_nsg_json_escape "$_nsg_tty")
        printf '{"ts":%s,"source":"bash-observer","event":"action_started","action_id":"%s","uid":%s,"pid":%s,"ppid":%s,"cwd":"%s","tty":"%s","sequence":%s,"command":"%s"}\n' \
            "${EPOCHREALTIME}" "$action_id" "$_nsg_uid" "$$" "$PPID" "$escaped_cwd" "$escaped_tty" \
            "$sequence" "$escaped_command" >> "$_nsg_command_log"
    }
    _nsg_save_history() {
        local command_status=$?
        history -a
        local sequence=${HISTCMD:-0}
        if [[ "$sequence" != "${_nsg_last_history_sequence:-}" ]]; then
            local command_text
            command_text=$(_nsg_current_command)
            if [[ -n "$command_text" ]]; then
                local action_id escaped_command escaped_cwd escaped_tty
                action_id="bash:${HOSTNAME:-container}:$$:${sequence}"
                escaped_command=$(_nsg_json_escape "$command_text")
                escaped_cwd=$(_nsg_json_escape "$PWD")
                escaped_tty=$(_nsg_json_escape "$_nsg_tty")
                printf '{"ts":%s,"source":"bash-observer","event":"command_completed","action_id":"%s","uid":%s,"pid":%s,"ppid":%s,"cwd":"%s","tty":"%s","sequence":%s,"exit_status":%s,"command":"%s"}\n' \
                    "${EPOCHREALTIME}" "$action_id" "$_nsg_uid" "$$" "$PPID" "$escaped_cwd" "$escaped_tty" \
                    "$sequence" "$command_status" "$escaped_command" >> "$_nsg_command_log"
            fi
            _nsg_last_history_sequence=$sequence
        fi
        if [[ -n ${_nsg_previous_prompt_command} ]]; then
            eval "${_nsg_previous_prompt_command}"
        fi
    }
    PROMPT_COMMAND=_nsg_save_history
    # PS0 is expanded after Bash reads a complete interactive command and just
    # before executing it. The command substitution is silent and requires no
    # cooperation from the user or program being observed.
    _nsg_previous_ps0="${PS0:-}"
    PS0="${_nsg_previous_ps0}"'$(_nsg_log_action_start)'
    unset _nsg_history_dir
fi
