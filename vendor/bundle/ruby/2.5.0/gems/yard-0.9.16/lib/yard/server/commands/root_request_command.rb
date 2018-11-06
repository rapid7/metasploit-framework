# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Serves requests from the root of the server
      class RootRequestCommand < Base
        include StaticFileHelpers

        def run
          static_template_file? || favicon? || not_found
        end
      end
    end
  end
end
