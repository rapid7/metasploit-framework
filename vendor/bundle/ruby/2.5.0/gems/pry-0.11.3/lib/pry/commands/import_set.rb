class Pry
  class Command::ImportSet < Pry::ClassCommand
    match 'import-set'
    group 'Commands'
    # TODO: Provide a better description with examples and a general conception
    # of this command.
    description 'Import a Pry command set.'

    banner <<-'BANNER'
      Import a Pry command set.
    BANNER

    def process(command_set_name)
      raise CommandError, "Provide a command set name" if command_set.nil?

      set = target.eval(arg_string)
      _pry_.commands.import set
    end
  end

  Pry::Commands.add_command(Pry::Command::ImportSet)
end
