module Sawyer
  class Response
    attr_reader :agent,
      :status,
      :headers,
      :data,
      :rels

    # Builds a Response after a completed request.
    #
    # agent - The Sawyer::Agent that is managing the API connection.
    # res   - A Faraday::Response.
    def initialize(agent, res, options = {})
      @agent   = agent
      @status  = res.status
      @headers = res.headers
      @env     = res.env
      @data    = @headers[:content_type] =~ /json|msgpack/ ? process_data(@agent.decode_body(res.body)) : res.body
      @rels    = process_rels
      @started = options[:sawyer_started]
      @ended   = options[:sawyer_ended]
    end

    # Turns parsed contents from an API response into a Resource or
    # collection of Resources.
    #
    # data - Either an Array or Hash parsed from JSON.
    #
    # Returns either a Resource or Array of Resources.
    def process_data(data)
      case data
      when Hash  then Resource.new(agent, data)
      when Array then data.map { |hash| process_data(hash) }
      when nil   then nil
      else data
      end
    end

    # Finds link relations from 'Link' response header
    #
    # Returns an array of Relations
    def process_rels
      links = ( @headers["Link"] || "" ).split(', ').map do |link|
        href, name = link.match(/<(.*?)>; rel="(\w+)"/).captures

        [name.to_sym, Relation.from_link(@agent, name, :href => href)]
      end

      Hash[*links.flatten]
    end

    def timing
      @timing ||= @ended - @started
    end

    def time
      @ended
    end

    def inspect
      %(#<#{self.class}: #{@status} @rels=#{@rels.inspect} @data=#{@data.inspect}>)
    end
  end
end
