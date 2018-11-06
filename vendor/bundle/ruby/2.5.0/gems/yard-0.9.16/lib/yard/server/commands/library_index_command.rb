# frozen_string_literal: true
module YARD
  module Server
    module Commands
      class LibraryIndexOptions < CLI::YardocOptions
        attr_accessor :adapter, :libraries
        default_attr :template, :doc_server
        default_attr :type, :library_list
        default_attr :serialize, false
      end

      # Returns the index of libraries served by the server.
      class LibraryIndexCommand < Base
        attr_accessor :options

        def run
          return unless path.empty?

          self.options = LibraryIndexOptions.new
          options.adapter = adapter
          options.libraries = adapter.libraries
          options.reset_defaults
          render
        end
      end
    end
  end
end
