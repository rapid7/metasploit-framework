class Pry
  class Command::SwitchTo < Pry::ClassCommand
    match 'switch-to'
    group 'Navigating Pry'
    description 'Start a new subsession on a binding in the current stack.'

    banner <<-'BANNER'
      Start a new subsession on a binding in the current stack (numbered by nesting).
    BANNER

    def process(selection)
      selection = selection.to_i

      if selection < 0 || selection > _pry_.binding_stack.size - 1
        raise CommandError, "Invalid binding index #{selection} - use `nesting` command to view valid indices."
      else
        Pry.start(_pry_.binding_stack[selection])
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::SwitchTo)
end
