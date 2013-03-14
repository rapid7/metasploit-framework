require 'sprockets/engines'
require 'sprockets/mime'
require 'sprockets/processor'
require 'sprockets/utils'

module Sprockets
  # `Processing` is an internal mixin whose public methods are exposed on
  # the `Environment` and `Index` classes.
  module Processing
    include Engines, Mime

    # Register a new mime type.
    def register_mime_type(mime_type, ext)
      # Overrides the global behavior to expire the index
      expire_index!
      @trail.append_extension(ext)
      super
    end

    # Returns an `Array` of format extension `String`s.
    #
    #     format_extensions
    #     # => ['.js', '.css']
    #
    def format_extensions
      @trail.extensions - @engines.keys
    end

    # Registers a new Engine `klass` for `ext`.
    def register_engine(ext, klass)
      # Overrides the global behavior to expire the index
      expire_index!
      add_engine_to_trail(ext, klass)
      super
    end

    # Deprecated alias for `preprocessors`.
    def processors(*args)
      preprocessors(*args)
    end

    # Returns an `Array` of `Processor` classes. If a `mime_type`
    # argument is supplied, the processors registered under that
    # extension will be returned.
    #
    # Preprocessors are ran before Postprocessors and Engine
    # processors.
    #
    # All `Processor`s must follow the `Tilt::Template` interface. It is
    # recommended to subclass `Tilt::Template`.
    def preprocessors(mime_type = nil)
      if mime_type
        @preprocessors[mime_type].dup
      else
        deep_copy_hash(@preprocessors)
      end
    end

    # Returns an `Array` of `Processor` classes. If a `mime_type`
    # argument is supplied, the processors registered under that
    # extension will be returned.
    #
    # Postprocessors are ran after Preprocessors and Engine processors.
    #
    # All `Processor`s must follow the `Tilt::Template` interface. It is
    # recommended to subclass `Tilt::Template`.
    def postprocessors(mime_type = nil)
      if mime_type
        @postprocessors[mime_type].dup
      else
        deep_copy_hash(@postprocessors)
      end
    end

    # Deprecated alias for `register_preprocessor`.
    def register_processor(*args, &block)
      register_preprocessor(*args, &block)
    end

    # Registers a new Preprocessor `klass` for `mime_type`.
    #
    #     register_preprocessor 'text/css', Sprockets::DirectiveProcessor
    #
    # A block can be passed for to create a shorthand processor.
    #
    #     register_preprocessor :my_processor do |context, data|
    #       data.gsub(...)
    #     end
    #
    def register_preprocessor(mime_type, klass, &block)
      expire_index!

      if block_given?
        name  = klass.to_s
        klass = Class.new(Processor) do
          @name      = name
          @processor = block
        end
      end

      @preprocessors[mime_type].push(klass)
    end

    # Registers a new Postprocessor `klass` for `mime_type`.
    #
    #     register_postprocessor 'text/css', Sprockets::CharsetNormalizer
    #
    # A block can be passed for to create a shorthand processor.
    #
    #     register_postprocessor :my_processor do |context, data|
    #       data.gsub(...)
    #     end
    #
    def register_postprocessor(mime_type, klass, &block)
      expire_index!

      if block_given?
        name  = klass.to_s
        klass = Class.new(Processor) do
          @name      = name
          @processor = block
        end
      end

      @postprocessors[mime_type].push(klass)
    end

    # Deprecated alias for `unregister_preprocessor`.
    def unregister_processor(*args)
      unregister_preprocessor(*args)
    end

    # Remove Preprocessor `klass` for `mime_type`.
    #
    #     unregister_preprocessor 'text/css', Sprockets::DirectiveProcessor
    #
    def unregister_preprocessor(mime_type, klass)
      expire_index!

      if klass.is_a?(String) || klass.is_a?(Symbol)
        klass = @preprocessors[mime_type].detect { |cls|
          cls.respond_to?(:name) &&
            cls.name == "Sprockets::Processor (#{klass})"
        }
      end

      @preprocessors[mime_type].delete(klass)
    end

    # Remove Postprocessor `klass` for `mime_type`.
    #
    #     unregister_postprocessor 'text/css', Sprockets::DirectiveProcessor
    #
    def unregister_postprocessor(mime_type, klass)
      expire_index!

      if klass.is_a?(String) || klass.is_a?(Symbol)
        klass = @postprocessors[mime_type].detect { |cls|
          cls.respond_to?(:name) &&
            cls.name == "Sprockets::Processor (#{klass})"
        }
      end

      @postprocessors[mime_type].delete(klass)
    end

    # Returns an `Array` of `Processor` classes. If a `mime_type`
    # argument is supplied, the processors registered under that
    # extension will be returned.
    #
    # Bundle Processors are ran on concatenated assets rather than
    # individual files.
    #
    # All `Processor`s must follow the `Tilt::Template` interface. It is
    # recommended to subclass `Tilt::Template`.
    def bundle_processors(mime_type = nil)
      if mime_type
        @bundle_processors[mime_type].dup
      else
        deep_copy_hash(@bundle_processors)
      end
    end

    # Registers a new Bundle Processor `klass` for `mime_type`.
    #
    #     register_bundle_processor  'text/css', Sprockets::CharsetNormalizer
    #
    # A block can be passed for to create a shorthand processor.
    #
    #     register_bundle_processor :my_processor do |context, data|
    #       data.gsub(...)
    #     end
    #
    def register_bundle_processor(mime_type, klass, &block)
      expire_index!

      if block_given?
        name  = klass.to_s
        klass = Class.new(Processor) do
          @name      = name
          @processor = block
        end
      end

      @bundle_processors[mime_type].push(klass)
    end

    # Remove Bundle Processor `klass` for `mime_type`.
    #
    #     unregister_bundle_processor 'text/css', Sprockets::CharsetNormalizer
    #
    def unregister_bundle_processor(mime_type, klass)
      expire_index!

      if klass.is_a?(String) || klass.is_a?(Symbol)
        klass = @bundle_processors[mime_type].detect { |cls|
          cls.respond_to?(:name) &&
            cls.name == "Sprockets::Processor (#{klass})"
        }
      end

      @bundle_processors[mime_type].delete(klass)
    end

    # Return CSS compressor or nil if none is set
    def css_compressor
      bundle_processors('text/css').detect { |klass|
        klass.respond_to?(:name) &&
          klass.name == 'Sprockets::Processor (css_compressor)'
      }
    end

    # Assign a compressor to run on `text/css` assets.
    #
    # The compressor object must respond to `compress` or `compile`.
    def css_compressor=(compressor)
      expire_index!

      unregister_bundle_processor 'text/css', :css_compressor
      return unless compressor

      register_bundle_processor 'text/css', :css_compressor do |context, data|
        compressor.compress(data)
      end
    end

    # Return JS compressor or nil if none is set
    def js_compressor
      bundle_processors('application/javascript').detect { |klass|
        klass.respond_to?(:name) &&
          klass.name == 'Sprockets::Processor (js_compressor)'
      }
    end

    # Assign a compressor to run on `application/javascript` assets.
    #
    # The compressor object must respond to `compress` or `compile`.
    def js_compressor=(compressor)
      expire_index!

      unregister_bundle_processor 'application/javascript', :js_compressor
      return unless compressor

      register_bundle_processor 'application/javascript', :js_compressor do |context, data|
        compressor.compress(data)
      end
    end

    private
      def add_engine_to_trail(ext, klass)
        @trail.append_extension(ext.to_s)

        if klass.respond_to?(:default_mime_type) && klass.default_mime_type
          if format_ext = extension_for_mime_type(klass.default_mime_type)
            @trail.alias_extension(ext.to_s, format_ext)
          end
        end
      end
  end
end
