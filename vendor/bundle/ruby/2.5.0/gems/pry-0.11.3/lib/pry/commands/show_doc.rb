require 'pry/commands/show_info'

class Pry
  class Command::ShowDoc < Command::ShowInfo
    include Pry::Helpers::DocumentationHelpers

    match 'show-doc'
    group 'Introspection'
    description 'Show the documentation for a method or class.'

    banner <<-BANNER
      Usage:   show-doc [OPTIONS] [METH]
      Aliases: ?

      Show the documentation for a method or class. Tries instance methods first and
      then methods by default.

      show-doc hi_method # docs for hi_method
      show-doc Pry       # for Pry class
      show-doc Pry -a    # for all definitions of Pry class (all monkey patches)
    BANNER

    # The docs for code_object prepared for display.
    def content_for(code_object)
      Code.new(render_doc_markup_for(code_object),
               start_line_for(code_object), :text).
        with_line_numbers(use_line_numbers?).to_s
    end

    # process the markup (if necessary) and apply colors
    def render_doc_markup_for(code_object)
      docs = docs_for(code_object)

      if code_object.command?
        # command '--help' shouldn't use markup highlighting
        docs
      else
        if docs.empty?
          raise CommandError, "No docs found for: #{
            obj_name ? obj_name : 'current context'
          }"
        end
        process_comment_markup(docs)
      end
    end

    # Return docs for the code_object, adjusting for whether the code_object
    # has yard docs available, in which case it returns those.
    # (note we only have to check yard docs for modules since they can
    # have multiple docs, but methods can only be doc'd once so we
    # dont need to check them)
    def docs_for(code_object)
      if code_object.module_with_yard_docs?
        # yard docs
        code_object.yard_doc
      else
        # normal docs (i.e comments above method/module/command)
        code_object.doc
      end
    end

    # Which sections to include in the 'header', can toggle: :owner,
    # :signature and visibility.
    def header_options
      super.merge :signature => true
    end

    # figure out start line of docs by back-calculating based on
    # number of lines in the comment and the start line of the code_object
    # @return [Fixnum] start line of docs
    def start_line_for(code_object)
      if code_object.command? || opts.present?(:'base-one')
         1
      else
        code_object.source_line.nil? ? 1 :
          (code_object.source_line - code_object.doc.lines.count)
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::ShowDoc)
  Pry::Commands.alias_command '?', 'show-doc'
end
