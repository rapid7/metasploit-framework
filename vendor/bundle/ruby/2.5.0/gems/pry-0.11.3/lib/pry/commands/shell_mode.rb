class Pry
  class Command::ShellMode < Pry::ClassCommand
    match 'shell-mode'
    group 'Input and Output'
    description 'Toggle shell mode. Bring in pwd prompt and file completion.'

    banner <<-'BANNER'
      Toggle shell mode. Bring in pwd prompt and file completion.
    BANNER

    def process
      case _pry_.prompt
      when Pry::SHELL_PROMPT
        _pry_.pop_prompt
        _pry_.custom_completions = _pry_.config.file_completions
      else
        _pry_.push_prompt Pry::SHELL_PROMPT
        _pry_.custom_completions = _pry_.config.command_completions
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::ShellMode)
  Pry::Commands.alias_command 'file-mode', 'shell-mode'
end
