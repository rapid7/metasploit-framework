# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Serves static content when no other router matches a request
      class StaticFileCommand < LibraryCommand
        include StaticFileHelpers

        DefaultMimeTypes['js'] = 'text/javascript'

        # Defines the paths used to search for static assets. To define an
        # extra path, use {YARD::Server.register_static_path} rather than
        # modifying this constant directly. Also note that files in the
        # document root will always take precedence over these paths.
        STATIC_PATHS = []

        def run
          static_template_file? || not_found
        end
      end
    end
  end
end
