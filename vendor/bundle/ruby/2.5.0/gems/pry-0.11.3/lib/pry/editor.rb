class Pry
  class Editor
    include Pry::Helpers::BaseHelpers
    include Pry::Helpers::CommandHelpers

    attr_reader :_pry_

    def initialize(_pry_)
      @_pry_ = _pry_
    end

    def edit_tempfile_with_content(initial_content, line=1)
      temp_file do |f|
        f.puts(initial_content)
        f.flush
        f.close(false)
        invoke_editor(f.path, line, true)
        File.read(f.path)
      end
    end

    def invoke_editor(file, line, blocking=true)
      raise CommandError, "Please set Pry.config.editor or export $VISUAL or $EDITOR" unless _pry_.config.editor

      editor_invocation = build_editor_invocation_string(file, line, blocking)
      return nil unless editor_invocation

      if jruby?
        open_editor_on_jruby(editor_invocation)
      else
        open_editor(editor_invocation)
      end
    end

    private

    # Generate the string that's used to start the editor. This includes
    # all the flags we want as well as the file and line number we
    # want to open at.
    def build_editor_invocation_string(file, line, blocking)

      if _pry_.config.editor.respond_to?(:call)
        args = [file, line, blocking][0...(_pry_.config.editor.arity)]
        _pry_.config.editor.call(*args)
      else
        sanitized_file = if windows?
                            file
                          else
                            Shellwords.escape(file)
                          end

        "#{_pry_.config.editor} #{blocking_flag_for_editor(blocking)} #{start_line_syntax_for_editor(sanitized_file, line)}"
      end
    end

    # Start the editor running, using the calculated invocation string
    def open_editor(editor_invocation)
      # Note we dont want to use Pry.config.system here as that
      # may be invoked non-interactively (i.e via Open4), whereas we want to
      # ensure the editor is always interactive
      system(*Shellwords.split(editor_invocation)) or raise CommandError, "`#{editor_invocation}` gave exit status: #{$?.exitstatus}"
    end

    # We need JRuby specific code here cos just shelling out using
    # system() appears to be pretty broken :/
    def open_editor_on_jruby(editor_invocation)
      begin
        require 'spoon'
        pid = Spoon.spawnp(*Shellwords.split(editor_invocation))
        Process.waitpid(pid)
      rescue FFI::NotFoundError
        system(editor_invocation)
      end
    end

    # Some editors that run outside the terminal allow you to control whether or
    # not to block the process from which they were launched (in this case, Pry).
    # For those editors, return the flag that produces the desired behavior.
    def blocking_flag_for_editor(blocking)
      case editor_name
      when /^emacsclient/
        '--no-wait' unless blocking
      when /^[gm]vim/
        '--nofork' if blocking
      when /^jedit/
        '-wait' if blocking
      when /^mate/, /^subl/, /^redcar/
        '-w' if blocking
      end
    end

    # Return the syntax for a given editor for starting the editor
    # and moving to a particular line within that file
    def start_line_syntax_for_editor(file_name, line_number)
      # special case for 1st line
      return file_name if line_number <= 1

      case editor_name
      when /^[gm]?vi/, /^emacs/, /^nano/, /^pico/, /^gedit/, /^kate/
        "+#{line_number} #{file_name}"
      when /^mate/, /^geany/
        "-l #{line_number} #{file_name}"
      when /^subl/
        "#{file_name}:#{line_number}"
      when /^uedit32/
        "#{file_name}/#{line_number}"
      when /^jedit/
        "#{file_name} +line:#{line_number}"
      when /^redcar/
        "-l#{line_number} #{file_name}"
      else
        if windows?
          "#{file_name}"
        else
          "+#{line_number} #{file_name}"
        end
      end
    end

    # Get the name of the binary that Pry.config.editor points to.
    #
    # This is useful for deciding which flags we pass to the editor as
    # we can just use the program's name and ignore any absolute paths.
    #
    # @example
    #   Pry.config.editor="/home/conrad/bin/textmate -w"
    #   editor_name
    #   # => textmate
    #
    def editor_name
      File.basename(_pry_.config.editor).split(" ").first
    end

  end
end
