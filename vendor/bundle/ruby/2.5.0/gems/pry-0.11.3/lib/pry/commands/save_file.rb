require 'pry/commands/code_collector'

class Pry
  class Command::SaveFile < Pry::ClassCommand
    match 'save-file'
    group 'Input and Output'
    description 'Export to a file using content from the REPL.'

    banner <<-'BANNER'
      Usage: save-file [OPTIONS] --to [FILE]

      Export to a file using content from the REPL.

      save-file my_method --to hello.rb
      save-file -i 1..10 --to hello.rb --append
      save-file show-method --to my_command.rb
      save-file sample_file.rb --lines 2..10 --to output_file.rb
    BANNER

    def options(opt)
      CodeCollector.inject_options(opt)

      opt.on :to=,        "Specify the output file path"
      opt.on :a, :append, "Append output to file"
    end

    def process
      @cc = CodeCollector.new(args, opts, _pry_)
      raise CommandError, "Found no code to save." if @cc.content.empty?

      if !file_name
        display_content
      else
        save_file
      end
    end

    def file_name
      opts[:to] || nil
    end

    def save_file
      File.open(file_name, mode) do |f|
        f.puts @cc.content
      end
      output.puts "#{file_name} successfully saved"
    end

    def display_content
      output.puts @cc.content
      output.puts "\n\n--\nPlease use `--to FILE` to export to a file."
      output.puts "No file saved!\n--"
    end

    def mode
      opts.present?(:append) ? "a" : "w"
    end
  end

  Pry::Commands.add_command(Pry::Command::SaveFile)
end
