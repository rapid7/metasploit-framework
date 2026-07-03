# -*- coding: binary -*-
module Msf::MCP
  module Logging
    module Sinks
      ###
      #
      # This class implements the LogSink interface and backs it against a
      # JSON file on disk.
      #
      ###
      class JsonFlatfile < Msf::MCP::Logging::Sinks::JsonStream

        #
        # Creates a JSON flatfile log sink instance that will be configured to log to
        # the supplied file path.
        #
        def initialize(file)
          super(File.new(file, 'a'))
        end

      end
    end
  end
end
