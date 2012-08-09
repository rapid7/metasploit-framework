require 'sprockets/eco_template'
require 'sprockets/ejs_template'
require 'sprockets/jst_processor'
require 'sprockets/utils'
require 'tilt'

module Sprockets
  # `Engines` provides a global and `Environment` instance registry.
  #
  # An engine is a type of processor that is bound to an filename
  # extension. `application.js.coffee` indicates that the
  # `CoffeeScriptTemplate` engine will be ran on the file.
  #
  # Extensions can be stacked and will be evaulated from right to
  # left. `application.js.coffee.erb` will first run `ERBTemplate`
  # then `CoffeeScriptTemplate`.
  #
  # All `Engine`s must follow the `Tilt::Template` interface. It is
  # recommended to subclass `Tilt::Template`.
  #
  # Its recommended that you register engine changes on your local
  # `Environment` instance.
  #
  #     environment.register_engine '.foo', FooProcessor
  #
  # The global registry is exposed for plugins to register themselves.
  #
  #     Sprockets.register_engine '.sass', SassTemplate
  #
  module Engines
    # Returns an `Array` of `Engine`s registered on the
    # `Environment`. If an `ext` argument is supplied, the `Engine`
    # register under that extension will be returned.
    #
    #     environment.engines
    #     # => [CoffeeScriptTemplate, SassTemplate, ...]
    #
    #     environment.engines('.coffee')
    #     # => CoffeeScriptTemplate
    #
    def engines(ext = nil)
      if ext
        ext = Sprockets::Utils.normalize_extension(ext)
        @engines[ext]
      else
        @engines.dup
      end
    end

    # Returns an `Array` of engine extension `String`s.
    #
    #     environment.engine_extensions
    #     # => ['.coffee', '.sass', ...]
    def engine_extensions
      @engines.keys
    end

    # Registers a new Engine `klass` for `ext`. If the `ext` already
    # has an engine registered, it will be overridden.
    #
    #     environment.register_engine '.coffee', CoffeeScriptTemplate
    #
    def register_engine(ext, klass)
      ext = Sprockets::Utils.normalize_extension(ext)
      @engines[ext] = klass
    end

    private
      def deep_copy_hash(hash)
        initial = Hash.new { |h, k| h[k] = [] }
        hash.inject(initial) { |h, (k, a)| h[k] = a.dup; h }
      end
  end
end
