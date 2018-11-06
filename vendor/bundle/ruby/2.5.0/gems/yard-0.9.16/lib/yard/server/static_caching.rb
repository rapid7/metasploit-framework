# frozen_string_literal: true
module YARD
  module Server
    # Implements static caching for requests.
    #
    # @see Router Router documentation for "Caching"
    module StaticCaching
      # Called by a router to return the cached object. By default, this
      # method performs disk-based caching. To perform other forms of caching,
      # implement your own +#check_static_cache+ method and mix the module into
      # the Router class.
      #
      # Note that caching does not occur here. This method simply checks for
      # the existence of cached data. To actually cache a response, see
      # {Commands::Base#cache}.
      #
      # @example Implementing In-Memory Cache Checking
      #   module MemoryCaching
      #     def check_static_cache
      #       # $memory_cache is filled by {Commands::Base#cache}
      #       cached_data = $memory_cache[request.path]
      #       if cached_data
      #         [200, {'Content-Type' => 'text/html'}, [cached_data]]
      #       else
      #         nil
      #       end
      #     end
      #   end
      #
      #   class YARD::Server::Router; include MemoryCaching; end
      # @return [Array(Numeric,Hash,Array)] the Rack-style response
      # @return [nil] if no cache is available and routing should continue
      # @see Commands::Base#cache
      def check_static_cache
        return nil unless adapter.document_root
        cache_path = File.join(adapter.document_root, request.path.sub(/\.html$/, '') + '.html')
        cache_path = cache_path.sub(%r{/\.html$}, '.html')
        if File.file?(cache_path)
          log.debug "Loading cache from disk: #{cache_path}"
          return [200, {'Content-Type' => 'text/html'}, [File.read_binary(cache_path)]]
        end
        nil
      end
    end
  end
end
