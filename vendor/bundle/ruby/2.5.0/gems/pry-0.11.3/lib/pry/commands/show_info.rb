class Pry
  class Command::ShowInfo < Pry::ClassCommand
    extend Pry::Helpers::BaseHelpers

    command_options :shellwords => false, :interpolate => false

    def initialize(*)
      super

      @used_super = nil
    end

    def options(opt)
      opt.on :s, :super, "Select the 'super' method. Can be repeated to traverse the ancestors", :as => :count
      opt.on :l, "line-numbers", "Show line numbers"
      opt.on :b, "base-one", "Show line numbers but start numbering at 1 (useful for `amend-line` and `play` commands)"
      opt.on :a, :all,  "Show all definitions and monkeypatches of the module/class"
    end

    def process
      code_object = Pry::CodeObject.lookup(obj_name, _pry_, :super => opts[:super])
      raise CommandError, no_definition_message if !code_object
      @original_code_object = code_object

      if !obj_name && code_object.c_module? && !opts[:all]
        result = "Warning: You're inside an object, whose class is defined by means\n" +
                 "         of the C Ruby API. Pry cannot display the information for\n" +
                 "         this class."
        if code_object.candidates.any?
          result += "\n         However, you can view monkey-patches applied to this class.\n" +
                    "         Just execute the same command with the '--all' switch."
        end
      elsif show_all_modules?(code_object)
        # show all monkey patches for a module

        result = content_and_headers_for_all_module_candidates(code_object)
      else
        # show a specific code object
        co = code_object_with_accessible_source(code_object)
        result = content_and_header_for_code_object(co)
      end

      set_file_and_dir_locals(code_object.source_file)
      _pry_.pager.page result
    end

    # This method checks whether the `code_object` is a WrappedModule,
    # if it is, then it returns the first candidate (monkeypatch) with
    # accessible source (or docs). If `code_object` is not a WrappedModule (i.e a
    # method or a command) then the `code_object` itself is just
    # returned.
    #
    # @return [Pry::WrappedModule, Pry::Method, Pry::Command]
    def code_object_with_accessible_source(code_object)
      if code_object.is_a?(WrappedModule)
        candidate = code_object.candidates.find(&:source)
        if candidate
          return candidate
        else
          raise CommandError, no_definition_message if !valid_superclass?(code_object)

          @used_super = true
          code_object_with_accessible_source(code_object.super)
        end
      else
        code_object
      end
    end

    def valid_superclass?(code_object)
      code_object.super && code_object.super.wrapped != Object
    end

    def content_and_header_for_code_object(code_object)
      header(code_object) << content_for(code_object)
    end

    def content_and_headers_for_all_module_candidates(mod)
      result = "Found #{mod.number_of_candidates} candidates for `#{mod.name}` definition:\n"
      mod.number_of_candidates.times do |v|
        candidate = mod.candidate(v)
        begin
          result << "\nCandidate #{v+1}/#{mod.number_of_candidates}: #{candidate.source_file} @ line #{candidate.source_line}:\n"
          content = content_for(candidate)

          result << "Number of lines: #{content.lines.count}\n\n" << content
        rescue Pry::RescuableException
          result << "\nNo content found.\n"
          next
        end
      end
      result
    end

    def no_definition_message
      "Couldn't locate a definition for #{obj_name}"
    end

    # Generate a header (meta-data information) for all the code
    # object types: methods, modules, commands, procs...
    def header(code_object)
      file_name, line_num = file_and_line_for(code_object)
      h = "\n#{Pry::Helpers::Text.bold('From:')} #{file_name} "
      h << code_object_header(code_object, line_num)
      h << "\n#{Pry::Helpers::Text.bold('Number of lines:')} " <<
        "#{content_for(code_object).lines.count}\n\n"
      h << Helpers::Text.bold('** Warning:') << " Cannot find code for #{@original_code_object.nonblank_name}. Showing superclass #{code_object.nonblank_name} instead. **\n\n" if @used_super
      h
    end

    def code_object_header(code_object, line_num)
      if code_object.real_method_object?
        method_header(code_object, line_num)

        # It sucks we have to test for both Pry::WrappedModule and WrappedModule::Candidate,
        # probably indicates a deep refactor needs to happen in those classes.
      elsif code_object.is_a?(Pry::WrappedModule) || code_object.is_a?(Pry::WrappedModule::Candidate)
        module_header(code_object, line_num)
      else
        ""
      end
    end

    def method_header(code_object, line_num)
      h = ""
      h << (code_object.c_method? ? "(C Method):" : "@ line #{line_num}:")
      h << method_sections(code_object)[:owner]
      h << method_sections(code_object)[:visibility]
      h << method_sections(code_object)[:signature]
      h
    end

    def module_header(code_object, line_num)
      h = ""
      h << "@ line #{line_num}:\n"
      h << text.bold(code_object.module? ? "Module" : "Class")
      h << " #{text.bold('name:')} #{code_object.nonblank_name}"

      if code_object.number_of_candidates > 1
        h << (text.bold("\nNumber of monkeypatches: ") << code_object.number_of_candidates.to_s)
        h << ". Use the `-a` option to display all available monkeypatches"
      end
      h
    end

    def method_sections(code_object)
      {
        :owner => "\n#{text.bold("Owner:")} #{code_object.owner || "N/A"}\n",
        :visibility => "#{text.bold("Visibility:")} #{code_object.visibility}",
        :signature => "\n#{text.bold("Signature:")} #{code_object.signature}"
      }.merge(header_options) { |key, old, new| (new && old).to_s }
    end

    def header_options
      {
        :owner => true,
        :visibility => true,
        :signature => nil
      }
    end

    def show_all_modules?(code_object)
      code_object.is_a?(Pry::WrappedModule) && opts.present?(:all)
    end

    def obj_name
      @obj_name ||= args.empty? ? nil : args.join(' ')
    end

    def use_line_numbers?
      opts.present?(:b) || opts.present?(:l)
    end

    def start_line_for(code_object)
      if opts.present?(:'base-one')
        1
      else
        code_object.source_line || 1
      end
    end

    # takes into account possible yard docs, and returns yard_file / yard_line
    # Also adjusts for start line of comments (using start_line_for), which it has to infer
    # by subtracting number of lines of comment from start line of code_object
    def file_and_line_for(code_object)
      if code_object.module_with_yard_docs?
        [code_object.yard_file, code_object.yard_line]
      else
        [code_object.source_file, start_line_for(code_object)]
      end
    end

    def complete(input)
      if input =~ /([^ ]*)#([a-z0-9_]*)\z/
        prefix, search = [$1, $2]
        methods = begin
                    Pry::Method.all_from_class(binding.eval(prefix))
                  rescue RescuableException
                    return super
                  end
        methods.map do |method|
          [prefix, method.name].join('#') if method.name.start_with?(search)
        end.compact
      else
        super
      end
    end
  end
end
