require 'digest/md5'
require 'fileutils'
require 'pathname'

module Sprockets
  module Cache
    # A simple file system cache store.
    #
    #     environment.cache = Sprockets::Cache::FileStore.new("/tmp")
    #
    class FileStore
      def initialize(root)
        @root = Pathname.new(root)
      end

      # Lookup value in cache
      def [](key)
        pathname = @root.join(key)
        pathname.exist? ? pathname.open('rb') { |f| Marshal.load(f) } : nil
      end

      # Save value to cache
      def []=(key, value)
        # Ensure directory exists
        FileUtils.mkdir_p @root.join(key).dirname

        @root.join(key).open('w') { |f| Marshal.dump(value, f)}
        value
      end
    end
  end
end
