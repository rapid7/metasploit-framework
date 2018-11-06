module Sawyer
  class Relation
    class Map
      # Tracks the available next actions for a resource, and
      # issues requests for them.
      def initialize
        @map = {}
      end

      # Adds a Relation to the map.
      #
      # rel - A Relation.
      #
      # Returns nothing.
      def <<(rel)
        @map[rel.name] = rel if rel
      end

      # Gets the raw Relation by its name.
      #
      # key - The Symbol name of the Relation.
      #
      # Returns a Relation.
      def [](key)
        @map[key.to_sym]
      end

      # Gets the number of mapped Relations.
      #
      # Returns an Integer.
      def size
        @map.size
      end

      # Gets a list of the Relation names.
      #
      # Returns an Array of Symbols in no specific order.
      def keys
        @map.keys
      end
      def to_hash
        pairs = @map.map do |k, v|
          [(k.to_s + "_url").to_sym, v.href]
        end
        Hash[pairs]
      end
      alias :to_h :to_hash

      def inspect
        hash = to_hash
        hash.respond_to?(:pretty_inspect) ? hash.pretty_inspect : hash.inspect
      end
    end

    attr_reader :agent,
      :name,
      :href_template,
      :method,
      :available_methods

    # Public: Builds an index of Relations from the value of a `_links`
    # property in a resource.  :get is the default method.  Any links with
    # multiple specified methods will get multiple relations created.
    #
    # index - The Hash mapping Relation names to the Hash Relation
    #         options.
    # rels  - A Relation::Map to store the Relations.
    #
    # Returns a Relation::Map
    def self.from_links(agent, index, rels = Map.new)
      if index.is_a?(Array)
        raise ArgumentError, "Links must be a hash of rel => {_href => '...'}: #{index.inspect}"
      end

      index.each do |name, options|
        rels << from_link(agent, name, options)
      end if index

      rels
    end

    # Public: Builds a single Relation from the given options.  These are
    # usually taken from a `_links` property in a resource.
    #
    # agent   - The Sawyer::Agent that made the request.
    # name    - The Symbol name of the Relation.
    # options - A Hash containing the other Relation properties.
    #           :href   - The String URL of the next action's location.
    #           :method - The optional String HTTP method.
    #
    # Returns a Relation.
    def self.from_link(agent, name, options)
      case options
      when Hash
        new agent, name, options[:href], options[:method]
      when String
        new agent, name, options
      end
    end

    # A Relation represents an available next action for a resource.
    #
    # agent  - The Sawyer::Agent that made the request.
    # name   - The Symbol name of the relation.
    # href   - The String URL of the location of the next action.
    # method - The Symbol HTTP method.  Default: :get
    def initialize(agent, name, href, method = nil)
      @agent = agent
      @name = name.to_sym
      @href = href
      @href_template = Addressable::Template.new(href.to_s)

      methods = nil

      if method.is_a? String
        if method.size.zero?
          method = nil
        else
          method.downcase!
          methods = method.split(',').map! do |m|
            m.strip!
            m.to_sym
          end
          method = methods.first
        end
      end

      @method = (method || :get).to_sym
      @available_methods = Set.new methods || [@method]
    end

    # Public: Makes an API request with the curent Relation using HEAD.
    #
    # data    - The Optional Hash or Resource body to be sent.  :get or :head
    #           requests can have no body, so this can be the options Hash
    #           instead.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def head(options = nil)
      options ||= {}
      options[:method] = :head
      call options
    end

    # Public: Makes an API request with the curent Relation using GET.
    #
    # data    - The Optional Hash or Resource body to be sent.  :get or :head
    #           requests can have no body, so this can be the options Hash
    #           instead.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def get(options = nil)
      options ||= {}
      options[:method] = :get
      call options
    end

    # Public: Makes an API request with the curent Relation using POST.
    #
    # data    - The Optional Hash or Resource body to be sent.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def post(data = nil, options = nil)
      options ||= {}
      options[:method] = :post
      call data, options
    end

    # Public: Makes an API request with the curent Relation using PUT.
    #
    # data    - The Optional Hash or Resource body to be sent.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def put(data = nil, options = nil)
      options ||= {}
      options[:method] = :put
      call data, options
    end

    # Public: Makes an API request with the curent Relation using PATCH.
    #
    # data    - The Optional Hash or Resource body to be sent.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def patch(data = nil, options = nil)
      options ||= {}
      options[:method] = :patch
      call data, options
    end

    # Public: Makes an API request with the curent Relation using DELETE.
    #
    # data    - The Optional Hash or Resource body to be sent.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def delete(data = nil, options = nil)
      options ||= {}
      options[:method] = :delete
      call data, options
    end

    # Public: Makes an API request with the curent Relation using OPTIONS.
    #
    # data    - The Optional Hash or Resource body to be sent.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Returns a Sawyer::Response.
    def options(data = nil, opt = nil)
      opt ||= {}
      opt[:method] = :options
      call data, opt
    end

    def href(options = nil)
      return @href if @href_template.nil?
      @href_template.expand(options || {}).to_s
    end

    # Public: Makes an API request with the curent Relation.
    #
    # data    - The Optional Hash or Resource body to be sent.  :get or :head
    #           requests can have no body, so this can be the options Hash
    #           instead.
    # options - Hash of option to configure the API request.
    #           :headers - Hash of API headers to set.
    #           :query   - Hash of URL query params to set.
    #           :method  - Symbol HTTP method.
    #
    # Raises ArgumentError if the :method value is not in @available_methods.
    # Returns a Sawyer::Response.
    def call(data = nil, options = nil)
      m = options && options[:method]
      if m && !@agent.allow_undefined_methods? && !@available_methods.include?(m == :head ? :get : m)
        raise ArgumentError, "method #{m.inspect} is not available: #{@available_methods.to_a.inspect}"
      end

      @agent.call m || @method, @href_template, data, options
    end

    def inspect
      %(#<#{self.class}: #{@name}: #{@method} #{@href_template}>)
    end
  end
end
