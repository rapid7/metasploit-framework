class Pry
  class Command::Nesting < Pry::ClassCommand
    match 'nesting'
    group 'Navigating Pry'
    description 'Show nesting information.'

    banner <<-'BANNER'
      Show nesting information.
    BANNER

    def process
      output.puts 'Nesting status:'
      output.puts '--'
      _pry_.binding_stack.each_with_index do |obj, level|
        if level == 0
          output.puts "#{level}. #{Pry.view_clip(obj.eval('self'))} (Pry top level)"
        else
          output.puts "#{level}. #{Pry.view_clip(obj.eval('self'))}"
        end
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::Nesting)
end
