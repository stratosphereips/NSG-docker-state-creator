# Sourced by Bash shells to preserve commands, their exit status, and session
# provenance.  Interactive shells source it through /etc/bash.bashrc; automated
# agents that run each command as a non-interactive ``bash -c '...'`` source it
# through BASH_ENV (see the Dockerfile).  This is supplementary to syscall and
# terminal recording.
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
    _nsg_ssh_connection=${SSH_CONNECTION:-}
    _nsg_ssh_client=${SSH_CLIENT:-}
    _nsg_remote_host=${REMOTEHOST:-}
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
        local command_text action_id escaped_command escaped_cwd escaped_tty escaped_hostname
        local escaped_ssh_connection escaped_ssh_client escaped_remote_host
        command_text=$(_nsg_current_command)
        [[ -n "$command_text" ]] || return 0
        action_id="bash:${HOSTNAME:-container}:$$:${sequence}"
        escaped_command=$(_nsg_json_escape "$command_text")
        escaped_cwd=$(_nsg_json_escape "$PWD")
        escaped_tty=$(_nsg_json_escape "$_nsg_tty")
        escaped_hostname=$(_nsg_json_escape "${HOSTNAME:-container}")
        escaped_ssh_connection=$(_nsg_json_escape "$_nsg_ssh_connection")
        escaped_ssh_client=$(_nsg_json_escape "$_nsg_ssh_client")
        escaped_remote_host=$(_nsg_json_escape "$_nsg_remote_host")
        printf '{"ts":%s,"source":"bash-observer","event":"action_started","action_id":"%s","container_hostname":"%s","ssh_connection":"%s","ssh_client":"%s","remote_host":"%s","uid":%s,"pid":%s,"ppid":%s,"cwd":"%s","tty":"%s","sequence":%s,"command":"%s"}\n' \
            "${EPOCHREALTIME}" "$action_id" "$escaped_hostname" "$escaped_ssh_connection" "$escaped_ssh_client" "$escaped_remote_host" "$_nsg_uid" "$$" "$PPID" "$escaped_cwd" "$escaped_tty" \
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
                local action_id escaped_command escaped_cwd escaped_tty escaped_hostname
                local escaped_ssh_connection escaped_ssh_client escaped_remote_host
                action_id="bash:${HOSTNAME:-container}:$$:${sequence}"
                escaped_command=$(_nsg_json_escape "$command_text")
                escaped_cwd=$(_nsg_json_escape "$PWD")
                escaped_tty=$(_nsg_json_escape "$_nsg_tty")
                escaped_hostname=$(_nsg_json_escape "${HOSTNAME:-container}")
                escaped_ssh_connection=$(_nsg_json_escape "$_nsg_ssh_connection")
                escaped_ssh_client=$(_nsg_json_escape "$_nsg_ssh_client")
                escaped_remote_host=$(_nsg_json_escape "$_nsg_remote_host")
                printf '{"ts":%s,"source":"bash-observer","event":"command_completed","action_id":"%s","container_hostname":"%s","ssh_connection":"%s","ssh_client":"%s","remote_host":"%s","uid":%s,"pid":%s,"ppid":%s,"cwd":"%s","tty":"%s","sequence":%s,"exit_status":%s,"command":"%s"}\n' \
                    "${EPOCHREALTIME}" "$action_id" "$escaped_hostname" "$escaped_ssh_connection" "$escaped_ssh_client" "$escaped_remote_host" "$_nsg_uid" "$$" "$PPID" "$escaped_cwd" "$escaped_tty" \
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

# Non-interactive shells (``bash -c '...'`` spawned by automated agents) never run
# PROMPT_COMMAND or PS0, so the interactive block above never fires for them and
# the command's exit status is lost.  Capture it with an EXIT trap instead, which
# runs when the ``-c`` command finishes.  For a simple command such as
# ``sshpass -p pw ssh host 'cat file'`` the shell's ``$?`` is the client's exit
# status, which distinguishes a successful pivot from a failed one.
if [[ $- != *i* ]] && [[ -n ${OBS_OUTPUT_DIR:-} ]]; then
    _nsg_ni_dir="${OBS_OUTPUT_DIR}/tty"
    mkdir -p "${_nsg_ni_dir}" 2>/dev/null || true
    _nsg_ni_uid=$(id -u)
    _nsg_ni_log="${_nsg_ni_dir}/commands-${_nsg_ni_uid}-${PPID}-$$.jsonl"
    _nsg_ni_json_escape() {
        local value=$1
        value=${value//\\/\\\\}
        value=${value//\"/\\\"}
        value=${value//$'\n'/\\n}
        value=${value//$'\r'/\\r}
        value=${value//$'\t'/\\t}
        printf '%s' "$value"
    }
    # Redact sshpass passwords so credentials never reach the command log.
    _nsg_ni_redact() {
        printf '%s' "$1" | sed -E \
            -e 's/(sshpass[[:space:]]+-p[[:space:]]+)[^[:space:]]+/\1xxxxxx/g' \
            -e 's/(sshpass[[:space:]]+-p)[^[:space:]-][^[:space:]]*/\1 xxxxxx/g' 2>/dev/null \
            || printf '%s' "$1"
    }
    # Recover the ``-c`` command string from this shell's own argv.  Returns
    # non-zero for shells started without ``-c`` (plain scripts, login shells),
    # which are left untouched.
    _nsg_ni_dash_c() {
        [[ -r "/proc/$$/cmdline" ]] || return 1
        local parts=() item found=
        while IFS= read -r -d '' item; do
            parts+=("$item")
        done < "/proc/$$/cmdline"
        local i
        for ((i = 0; i < ${#parts[@]}; i++)); do
            if [[ -n $found ]]; then
                printf '%s' "${parts[i]}"
                return 0
            fi
            [[ ${parts[i]} == "-c" ]] && found=1
        done
        return 1
    }
    _nsg_ni_log_exit() {
        local command_status=$?
        local command_text
        command_text=$(_nsg_ni_dash_c) || return 0
        [[ -n "$command_text" ]] || return 0
        # Skip the observer's own helper shells to avoid recording and reacting
        # to the measurement apparatus.
        case "$command_text" in
            *nsg-observer*|*"$OBS_OUTPUT_DIR"*) return 0 ;;
        esac
        command_text=$(_nsg_ni_redact "$command_text")
        local action_id escaped_command escaped_cwd escaped_hostname
        action_id="bash:${HOSTNAME:-container}:$$:0"
        escaped_command=$(_nsg_ni_json_escape "$command_text")
        escaped_cwd=$(_nsg_ni_json_escape "$PWD")
        escaped_hostname=$(_nsg_ni_json_escape "${HOSTNAME:-container}")
        printf '{"ts":%s,"source":"bash-observer","event":"command_completed","action_id":"%s","container_hostname":"%s","uid":%s,"pid":%s,"ppid":%s,"cwd":"%s","sequence":0,"exit_status":%s,"command":"%s"}\n' \
            "${EPOCHREALTIME}" "$action_id" "$escaped_hostname" "$_nsg_ni_uid" "$$" "$PPID" "$escaped_cwd" "$command_status" "$escaped_command" >> "$_nsg_ni_log"
    }
    trap _nsg_ni_log_exit EXIT
    unset _nsg_ni_dir
fi
