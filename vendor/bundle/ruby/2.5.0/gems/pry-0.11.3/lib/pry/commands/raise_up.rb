class Pry
  # N.B. using a regular expresion here so that "raise-up 'foo'" does the right thing.
  class Command::RaiseUp < Pry::ClassCommand
    match(/raise-up(!?\b.*)/)
    group 'Context'
    description 'Raise an exception out of the current pry instance.'
    command_options :listing => 'raise-up'

    banner <<-BANNER
      Raise up, like exit, allows you to quit pry. Instead of returning a value
      however, it raises an exception. If you don't provide the exception to be
      raised, it will use the most recent exception (in pry `_ex_`).

      When called as raise-up! (with an exclamation mark), this command raises the
      exception through any nested prys you have created by "cd"ing into objects.

      raise-up "get-me-out-of-here"

      # This is equivalent to the command above.
      raise "get-me-out-of-here"
      raise-up
    BANNER

    def process
      return _pry.pager.page help if captures[0] =~ /(-h|--help)\b/
      # Handle 'raise-up', 'raise-up "foo"', 'raise-up RuntimeError, 'farble' in a rubyesque manner
      target.eval("_pry_.raise_up#{captures[0]}")
    end
  end

  Pry::Commands.add_command(Pry::Command::RaiseUp)
end
