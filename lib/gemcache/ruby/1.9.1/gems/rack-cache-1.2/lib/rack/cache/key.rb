require 'rack/utils'

module Rack::Cache
  class Key
    include Rack::Utils

    # Implement .call, since it seems like the "Rack-y" thing to do. Plus, it
    # opens the door for cache key generators to just be blocks.
    def self.call(request)
      new(request).generate
    end

    def initialize(request)
      @request = request
    end

    # Generate a normalized cache key for the request.
    def generate
      parts = []
      parts << @request.scheme << "://"
      parts << @request.host

      if @request.scheme == "https" && @request.port != 443 ||
          @request.scheme == "http" && @request.port != 80
        parts << ":" << @request.port.to_s
      end

      parts << @request.script_name
      parts << @request.path_info

      if qs = query_string
        parts << "?"
        parts << qs
      end

      parts.join
    end

  private
    # Build a normalized query string by alphabetizing all keys/values
    # and applying consistent escaping.
    def query_string
      return nil if @request.query_string.nil?

      @request.query_string.split(/[&;] */n).
        map { |p| unescape(p).split('=', 2) }.
        sort.
        map { |k,v| "#{escape(k)}=#{escape(v)}" }.
        join('&')
    end
  end
end
