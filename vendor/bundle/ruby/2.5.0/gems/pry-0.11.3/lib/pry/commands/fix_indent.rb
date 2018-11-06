class Pry
  class Command::FixIndent < Pry::ClassCommand
    match 'fix-indent'
    group 'Input and Output'

    description "Correct the indentation for contents of the input buffer"

    banner <<-USAGE
      Usage: fix-indent
    USAGE

    def process
      indented_str = Pry::Indent.indent(eval_string)
      eval_string.replace indented_str
    end
  end

  Pry::Commands.add_command(Pry::Command::FixIndent)
end
