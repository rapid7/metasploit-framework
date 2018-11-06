class Pry
  class Command::Cd < Pry::ClassCommand
    match 'cd'
    group 'Context'
    description 'Move into a new context (object or scope).'

    banner <<-'BANNER'
      Usage: cd [OPTIONS] [--help]

      Move into new context (object or scope). As in UNIX shells use `cd ..` to go
      back, `cd /` to return to Pry top-level and `cd -` to toggle between last two
      scopes. Complex syntax (e.g `cd ../@x/@y`) also supported.

      cd @x
      cd ..
      cd /
      cd -

      https://github.com/pry/pry/wiki/State-navigation#wiki-Changing_scope
    BANNER

    def process
      state.old_stack ||= []

      if arg_string.strip == "-"
        unless state.old_stack.empty?
          _pry_.binding_stack, state.old_stack = state.old_stack, _pry_.binding_stack
        end
      else
        stack = ObjectPath.new(arg_string, _pry_.binding_stack).resolve

        if stack && stack != _pry_.binding_stack
          state.old_stack = _pry_.binding_stack
          _pry_.binding_stack = stack
        end
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::Cd)
end
