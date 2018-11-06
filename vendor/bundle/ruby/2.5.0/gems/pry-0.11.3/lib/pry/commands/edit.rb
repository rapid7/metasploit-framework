class Pry
  class Command::Edit < Pry::ClassCommand
    require 'pry/commands/edit/exception_patcher'
    require 'pry/commands/edit/file_and_line_locator'

    match 'edit'
    group 'Editing'
    description 'Invoke the default editor on a file.'

    banner <<-'BANNER'
      Usage: edit [--no-reload|--reload|--patch] [--line LINE] [--temp|--ex|FILE[:LINE]|OBJECT|--in N]

      Open a text editor. When no FILE is given, edits the pry input buffer.
      When a method/module/command is given, the code is opened in an editor.
      Ensure `Pry.config.editor` or `_pry_.config.editor` is set to your editor of choice.

      edit sample.rb                edit -p MyClass#my_method
      edit sample.rb --line 105     edit MyClass
      edit MyClass#my_method        edit --ex
      edit --method                 edit --ex -p

      https://github.com/pry/pry/wiki/Editor-integration#wiki-Edit_command
    BANNER

    def options(opt)
      opt.on :e, :ex,      "Open the file that raised the most recent exception (_ex_.file)",
                           :optional_argument => true, :as => Integer
      opt.on :i, :in,      "Open a temporary file containing the Nth input expression. N may be a range",
                           :optional_argument => true, :as => Range, :default => -1..-1
      opt.on :t, :temp,    "Open an empty temporary file"
      opt.on :l, :line,    "Jump to this line in the opened file",
                           :argument => true, :as => Integer
      opt.on :n, :"no-reload", "Don't automatically reload the edited file"
      opt.on :c, :current, "Open the current __FILE__ and at __LINE__ (as returned by `whereami`)"
      opt.on :r, :reload,  "Reload the edited code immediately (default for ruby files)"
      opt.on :p, :patch,   "Instead of editing the object's file, try to edit in a tempfile and apply as a monkey patch"
      opt.on :m, :method,  "Explicitly edit the _current_ method (when inside a method context)."
    end

    def process
      if bad_option_combination?
        raise CommandError, "Only one of --ex, --temp, --in, --method and FILE may be specified."
      end

      if repl_edit?
        # code defined in pry, eval'd within pry.
        repl_edit
      elsif runtime_patch?
        # patch code without persisting changes, implies future changes are patches
        apply_runtime_patch
      else
        # code stored in actual files, eval'd at top-level
        file_edit
      end
    end

    def repl_edit?
      !opts.present?(:ex) && !opts.present?(:current) && !opts.present?(:method) &&
        filename_argument.empty?
    end

    def repl_edit
      content = Pry::Editor.new(_pry_).edit_tempfile_with_content(initial_temp_file_content,
                                                       initial_temp_file_content.lines.count)
      silence_warnings do
        eval_string.replace content
      end
    end

    def file_based_exception?
      opts.present?(:ex) && !opts.present?(:patch)
    end

    def runtime_patch?
       !file_based_exception? && (opts.present?(:patch) || previously_patched?(code_object) || pry_method?(code_object))
    end

    def apply_runtime_patch
      if patch_exception?
        ExceptionPatcher.new(_pry_, state, file_and_line_for_current_exception).perform_patch
      else
        if code_object.is_a?(Pry::Method)
          code_object.redefine Pry::Editor.new(_pry_).edit_tempfile_with_content(code_object.source)
        else
          raise NotImplementedError, "Cannot yet patch #{code_object} objects!"
        end
      end
    end

    def ensure_file_name_is_valid(file_name)
      raise CommandError, "Cannot find a valid file for #{filename_argument}" if !file_name
      raise CommandError, "#{file_name} is not a valid file name, cannot edit!" if not_a_real_file?(file_name)
    end

    def file_and_line_for_current_exception
      FileAndLineLocator.from_exception(_pry_.last_exception, opts[:ex].to_i)
    end

    def file_and_line
      file_name, line = if opts.present?(:current)
                          FileAndLineLocator.from_binding(target)
                        elsif opts.present?(:ex)
                          file_and_line_for_current_exception
                        elsif code_object
                          FileAndLineLocator.from_code_object(code_object, filename_argument)
                        else
                          # when file and line are passed as a single arg, e.g my_file.rb:30
                          FileAndLineLocator.from_filename_argument(filename_argument)
                        end

      [file_name, opts.present?(:line) ? opts[:l].to_i : line]
    end

    def file_edit
      file_name, line = file_and_line

      ensure_file_name_is_valid(file_name)

      Pry::Editor.new(_pry_).invoke_editor(file_name, line, reload?(file_name))
      set_file_and_dir_locals(file_name)

      if reload?(file_name)
        silence_warnings do
          load file_name
        end
      end
    end

    def filename_argument
      args.join(' ')
    end

    def code_object
      @code_object ||= !probably_a_file?(filename_argument) &&
        Pry::CodeObject.lookup(filename_argument, _pry_)
    end

    def pry_method?(code_object)
      code_object.is_a?(Pry::Method) &&
        code_object.pry_method?
    end

    def previously_patched?(code_object)
      code_object.is_a?(Pry::Method) && Pry::Method::Patcher.code_for(code_object.source_location.first)
    end

    def patch_exception?
      opts.present?(:ex) && opts.present?(:patch)
    end

    def bad_option_combination?
      [opts.present?(:ex), opts.present?(:temp),
       opts.present?(:in), opts.present?(:method), !filename_argument.empty?].count(true) > 1
    end

    def input_expression
      case opts[:i]
      when Range
        (_pry_.input_array[opts[:i]] || []).join
      when Integer
        _pry_.input_array[opts[:i]] || ""
      else
        raise Pry::CommandError, "Not a valid range: #{opts[:i]}"
      end
    end

    def reloadable?
      opts.present?(:reload) || opts.present?(:ex)
    end

    def never_reload?
      opts.present?(:'no-reload') || _pry_.config.disable_auto_reload
    end

    def reload?(file_name="")
      (reloadable? || file_name.end_with?(".rb")) && !never_reload?
    end

    def initial_temp_file_content
      case
      when opts.present?(:temp)
        ""
      when opts.present?(:in)
        input_expression
      when eval_string.strip != ""
        eval_string
      else
        _pry_.input_array.reverse_each.find { |x| x && x.strip != "" } || ""
      end
    end

    def probably_a_file?(str)
      [".rb", ".c", ".py", ".yml", ".gemspec"].include?(File.extname(str)) ||
        str =~ /\/|\\/
    end
  end

  Pry::Commands.add_command(Pry::Command::Edit)
end
