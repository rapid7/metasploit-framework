module MultiJson
  class DecodeError < StandardError
    attr_reader :data
    def initialize(message, backtrace, data)
      super(message)
      self.set_backtrace(backtrace)
      @data = data
    end
  end

  module_function

  @engine = nil

  # Get the current engine class.
  def engine
    return @engine if @engine
    self.engine = self.default_engine
    @engine
  end

  REQUIREMENT_MAP = [
    ["yajl", :yajl],
    ["json", :json_gem],
    ["json/pure", :json_pure]
  ]

  DEFAULT_ENGINE_WARNING = 'Warning: multi_json is using default ok_json engine. Suggested action: require and load an appropriate JSON library.'

  # The default engine based on what you currently
  # have loaded and installed. First checks to see
  # if any engines are already loaded, then checks
  # to see which are installed if none are loaded.
  def default_engine
    return :yajl if defined?(::Yajl)
    return :json_gem if defined?(::JSON)

    REQUIREMENT_MAP.each do |(library, engine)|
      begin
        require library
        return engine
      rescue LoadError
        next
      end
    end

    Kernel.warn DEFAULT_ENGINE_WARNING
    :ok_json
  end

  # Set the JSON parser utilizing a symbol, string, or class.
  # Supported by default are:
  #
  # * <tt>:json_gem</tt>
  # * <tt>:json_pure</tt>
  # * <tt>:ok_json</tt>
  # * <tt>:yajl</tt>
  def engine=(new_engine)
    case new_engine
    when String, Symbol
      require "multi_json/engines/#{new_engine}"
      @engine = MultiJson::Engines.const_get("#{new_engine.to_s.split('_').map{|s| s.capitalize}.join('')}")
    when Class
      @engine = new_engine
    else
      raise "Did not recognize your engine specification. Please specify either a symbol or a class."
    end
  end

  # Decode a JSON string into Ruby.
  #
  # <b>Options</b>
  #
  # <tt>:symbolize_keys</tt> :: If true, will use symbols instead of strings for the keys.
  def decode(string, options = {})
    engine.decode(string, options)
  rescue engine::ParseError => exception
    raise DecodeError.new(exception.message, exception.backtrace, string)
  end

  # Encodes a Ruby object as JSON.
  def encode(object, options = {})
    engine.encode(object, options)
  end
end
