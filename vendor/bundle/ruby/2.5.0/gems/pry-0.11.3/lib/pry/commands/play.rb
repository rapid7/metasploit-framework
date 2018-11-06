class Pry
  class Command::Play < Pry::ClassCommand
    match 'play'
    group 'Editing'
    description 'Playback a string variable, method, line, or file as input.'

    banner <<-'BANNER'
      Usage: play [OPTIONS] [--help]

      The play command enables you to replay code from files and methods as if they
      were entered directly in the Pry REPL.

      play --lines 149..153   # assumes current context
      play -i 20 --lines 1..3 # assumes lines of the input expression at 20
      play -o 4               # the output of an expression at 4
      play Pry#repl -l 1..-1  # play the contents of Pry#repl method
      play -e 2               # play from specified line until end of valid expression
      play hello.rb           # play a file
      play Rakefile -l 5      # play line 5 of a file
      play -d hi              # play documentation of hi method
      play hi --open          # play hi method and leave it open

      https://github.com/pry/pry/wiki/User-Input#wiki-Play
    BANNER

    def options(opt)
      CodeCollector.inject_options(opt)

      opt.on :open, 'Plays the selected content except the last line. Useful' \
                    ' for replaying methods and leaving the method definition' \
                    ' "open". `amend-line` can then be used to' \
                    ' modify the method.'

      opt.on :e, :expression=, 'Executes until end of valid expression', :as => Integer
      opt.on :p, :print, 'Prints executed code'
    end

    def process
      @cc = CodeCollector.new(args, opts, _pry_)

      perform_play
      show_input
    end

    def perform_play
      eval_string << content_after_options
      run "fix-indent"
    end

    def show_input
      if opts.present?(:print) or !Pry::Code.complete_expression?(eval_string)
        run "show-input"
      end
    end


    def content_after_options
      if opts.present?(:open)
        restrict_to_lines(content, (0..-2))
      elsif opts.present?(:expression)
        content_at_expression
      else
        content
      end
    end

    def content_at_expression
      code_object.expression_at(opts[:expression])
    end

    def code_object
      Pry::Code.new(content)
    end

    def should_use_default_file?
      !args.first && !opts.present?(:in) && !opts.present?(:out)
    end

    def content
      if should_use_default_file?
        file_content
      else
        @cc.content
      end
    end

    # The file to play from when no code object is specified.
    # e.g `play --lines 4..10`
    def default_file
      target.eval("__FILE__") && File.expand_path(target.eval("__FILE__"))
    end

    def file_content
      if default_file && File.exist?(default_file)
        @cc.restrict_to_lines(File.read(default_file), @cc.line_range)
      else
        raise CommandError, "File does not exist! File was: #{default_file.inspect}"
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::Play)
end
