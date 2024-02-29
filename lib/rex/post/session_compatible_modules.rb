# -*- coding: binary -*-

module Rex
  module Post
    ###
    #
    # This module provides a list of modules that are compatible with the current session
    #
    ###
    module SessionCompatibleModules

      # @return [Array<String>]
      def session_compatible_modules
        # Use the built in search command functionality to get a list of search results
        search_params = { 'session_type' => [[self.session.type], []] }
        Msf::Modules::Metadata::Cache.instance.find(search_params)
      end

      # @return [String]
      def format_session_compatible_modules
        <<~EOF
          This session also works with the following modules:

            #{session_compatible_modules.flat_map(&:fullname).join("\n  ")}

        EOF
      end
    end
  end
end
