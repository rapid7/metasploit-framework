require 'tilt/template'

module Tilt
  # ERB template implementation. See:
  # http://www.ruby-doc.org/stdlib/libdoc/erb/rdoc/classes/ERB.html
  class ERBTemplate < Template
    @@default_output_variable = '_erbout'

    def self.default_output_variable
      @@default_output_variable
    end

    def self.default_output_variable=(name)
      @@default_output_variable = name
    end

    def self.engine_initialized?
      defined? ::ERB
    end

    def initialize_engine
      require_template_library 'erb'
    end

    def prepare
      @outvar = options[:outvar] || self.class.default_output_variable
      options[:trim] = '<>' if options[:trim].nil? || options[:trim] == true
      @engine = ::ERB.new(data, options[:safe], options[:trim], @outvar)
    end

    def precompiled_template(locals)
      source = @engine.src
      source
    end

    def precompiled_preamble(locals)
      <<-RUBY
        begin
          __original_outvar = #{@outvar} if defined?(#{@outvar})
          #{super}
      RUBY
    end

    def precompiled_postamble(locals)
      <<-RUBY
          #{super}
        ensure
          #{@outvar} = __original_outvar
        end
      RUBY
    end

    # ERB generates a line to specify the character coding of the generated
    # source in 1.9. Account for this in the line offset.
    if RUBY_VERSION >= '1.9.0'
      def precompiled(locals)
        source, offset = super
        [source, offset + 1]
      end
    end
  end

  # Erubis template implementation. See:
  # http://www.kuwata-lab.com/erubis/
  #
  # ErubisTemplate supports the following additional options, which are not
  # passed down to the Erubis engine:
  #
  #   :engine_class   allows you to specify a custom engine class to use
  #                   instead of the default (which is ::Erubis::Eruby).
  #
  #   :escape_html    when true, ::Erubis::EscapedEruby will be used as
  #                   the engine class instead of the default. All content
  #                   within <%= %> blocks will be automatically html escaped.
  class ErubisTemplate < ERBTemplate
    def self.engine_initialized?
      defined? ::Erubis
    end

    def initialize_engine
      require_template_library 'erubis'
    end

    def prepare
      @outvar = options.delete(:outvar) || self.class.default_output_variable
      @options.merge!(:preamble => false, :postamble => false, :bufvar => @outvar)
      engine_class = options.delete(:engine_class)
      engine_class = ::Erubis::EscapedEruby if options.delete(:escape_html)
      @engine = (engine_class || ::Erubis::Eruby).new(data, options)
    end

    def precompiled_preamble(locals)
      [super, "#{@outvar} = _buf = ''"].join("\n")
    end

    def precompiled_postamble(locals)
      [@outvar, super].join("\n")
    end

    # Erubis doesn't have ERB's line-off-by-one under 1.9 problem.
    # Override and adjust back.
    if RUBY_VERSION >= '1.9.0'
      def precompiled(locals)
        source, offset = super
        [source, offset - 1]
      end
    end
  end
end

