class Pry
  class Command::ExitAll < Pry::ClassCommand
    match 'exit-all'
    group 'Navigating Pry'
    description 'End the current Pry session.'

    banner <<-'BANNER'
      Usage:   exit-all [--help]
      Aliases: !!@

      End the current Pry session (popping all bindings and returning to caller).
      Accepts optional return value.
    BANNER

    def process
      # calculate user-given value
      exit_value = target.eval(arg_string)

      # clear the binding stack
      _pry_.binding_stack.clear

      # break out of the repl loop
      throw(:breakout, exit_value)
    end
  end

  Pry::Commands.add_command(Pry::Command::ExitAll)
  Pry::Commands.alias_command '!!@', 'exit-all'
end
