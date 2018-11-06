# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Returns a list of objects of a specific type
      class ListCommand < LibraryCommand
        include Templates::Helpers::BaseHelper

        def run
          Registry.load_all
          options.update(:objects => run_verifier(Registry.all(:class, :module)))
          list_type = request.path.split('/').last
          meth = "generate_#{list_type}_list"
          tpl = fulldoc_template
          if tpl.respond_to?(meth)
            tpl.send(meth)
            cache(tpl.contents)
          else
            not_found
          end
        end
      end
    end
  end
end
