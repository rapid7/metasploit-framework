# frozen_string_literal: true
module YARD
  module Server
    # Registers a static path to be used in static asset lookup.
    # @param [String] path the pathname to register
    # @return [void]
    # @since 0.6.2
    def self.register_static_path(path)
      static_paths = Commands::StaticFileCommand::STATIC_PATHS
      static_paths.push(path) unless static_paths.include?(path)
    end
  end
end
