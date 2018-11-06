require 'pry/commands/show_info'

class Pry
  class Command::ShowSource < Command::ShowInfo
    match 'show-source'
    group 'Introspection'
    description 'Show the source for a method or class.'

    banner <<-'BANNER'
      Usage:   show-source [OPTIONS] [METH|CLASS]
      Aliases: $, show-method

      Show the source for a method or class. Tries instance methods first and then
      methods by default.

      show-source hi_method
      show-source hi_method
      show-source Pry#rep     # source for Pry#rep method
      show-source Pry         # for Pry class
      show-source Pry -a      # for all Pry class definitions (all monkey patches)
      show-source Pry.foo -e  # for class of the return value of expression `Pry.foo`
      show-source Pry --super # for superclass of Pry (Object class)

      https://github.com/pry/pry/wiki/Source-browsing#wiki-Show_method
    BANNER

    def options(opt)
      opt.on :e, :eval, "evaluate the command's argument as a ruby expression and show the class its return value"
      super(opt)
    end

    def process
      if opts.present?(:e)
        obj = target.eval(args.first)
        self.args = Array.new(1) { Module === obj ? obj.name : obj.class.name }
      end
      super
    end

    # The source for code_object prepared for display.
    def content_for(code_object)
      Code.new(code_object.source, start_line_for(code_object)).
        with_line_numbers(use_line_numbers?).highlighted
    end
  end

  Pry::Commands.add_command(Pry::Command::ShowSource)
  Pry::Commands.alias_command 'show-method', 'show-source'
  Pry::Commands.alias_command '$', 'show-source'
end
