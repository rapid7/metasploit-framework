class Pry
  class Command::SimplePrompt < Pry::ClassCommand
    match 'simple-prompt'
    group 'prompts'
    description 'Toggle the simple prompt.'

    banner <<-'BANNER'
      Toggle the simple prompt.
    BANNER

    def process
      case _pry_.prompt
      when Pry::SIMPLE_PROMPT
        _pry_.pop_prompt
      else
        _pry_.push_prompt Pry::SIMPLE_PROMPT
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::SimplePrompt)
end
