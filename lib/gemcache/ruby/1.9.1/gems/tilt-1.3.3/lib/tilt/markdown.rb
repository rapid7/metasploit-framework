require 'tilt/template'

module Tilt
  # Discount Markdown implementation. See:
  # http://github.com/rtomayko/rdiscount
  #
  # RDiscount is a simple text filter. It does not support +scope+ or
  # +locals+. The +:smart+ and +:filter_html+ options may be set true
  # to enable those flags on the underlying RDiscount object.
  class RDiscountTemplate < Template
    self.default_mime_type = 'text/html'

    ALIAS = {
      :escape_html => :filter_html,
      :smartypants => :smart
    }

    FLAGS = [:smart, :filter_html, :smartypants, :escape_html]

    def flags
      FLAGS.select { |flag| options[flag] }.map { |flag| ALIAS[flag] || flag }
    end

    def self.engine_initialized?
      defined? ::RDiscount
    end

    def initialize_engine
      require_template_library 'rdiscount'
    end

    def prepare
      @engine = RDiscount.new(data, *flags)
      @output = nil
    end

    def evaluate(scope, locals, &block)
      @output ||= @engine.to_html
    end
  end

  # Upskirt Markdown implementation. See:
  # https://github.com/tanoku/redcarpet
  #
  # Supports both Redcarpet 1.x and 2.x
  class RedcarpetTemplate < Template
    def self.engine_initialized?
      defined? ::Redcarpet
    end

    def initialize_engine
      require_template_library 'redcarpet'
    end

    def prepare
      klass = [Redcarpet1, Redcarpet2].detect { |e| e.engine_initialized? }
      @engine = klass.new(file, line, options) { data }
    end

    def evaluate(scope, locals, &block)
      @engine.evaluate(scope, locals, &block)
    end

    # Compatibility mode for Redcarpet 1.x
    class Redcarpet1 < RDiscountTemplate
      self.default_mime_type = 'text/html'

      def self.engine_initialized?
        defined? ::RedcarpetCompat
      end

      def prepare
        @engine = RedcarpetCompat.new(data, *flags)
        @output = nil
      end
    end

    # Future proof mode for Redcarpet 2.x (not yet released)
    class Redcarpet2 < Template
      self.default_mime_type = 'text/html'

      def self.engine_initialized?
        defined? ::Redcarpet::Render
      end

      def generate_renderer
        renderer = options.delete(:renderer) || Redcarpet::Render::HTML
        return renderer unless options.delete(:smartypants)
        return renderer if renderer <= Redcarpet::Render::SmartyPants

        if renderer == Redcarpet::Render::XHTML
          Redcarpet::Render::SmartyHTML.new(:xhtml => true)
        elsif renderer == Redcarpet::Render::HTML
          Redcarpet::Render::SmartyHTML
        elsif renderer.is_a? Class
          Class.new(renderer) { include Redcarpet::Render::SmartyPants }
        else
          renderer.extend Redcarpet::Render::SmartyPants
        end
      end

      def prepare
        # try to support the same aliases
        RDiscountTemplate::ALIAS.each do |opt, aka|
          next if options.key? opt or not options.key? aka
          options[opt] = options.delete(aka)
        end

        # only raise an exception if someone is trying to enable :escape_html
        options.delete(:escape_html) unless options[:escape_html]

        @engine = Redcarpet::Markdown.new(generate_renderer, options)
        @output = nil
      end

      def evaluate(scope, locals, &block)
        @output ||= @engine.render(data)
      end
    end
  end

  # BlueCloth Markdown implementation. See:
  # http://deveiate.org/projects/BlueCloth/
  class BlueClothTemplate < Template
    self.default_mime_type = 'text/html'

    def self.engine_initialized?
      defined? ::BlueCloth
    end

    def initialize_engine
      require_template_library 'bluecloth'
    end

    def prepare
      @engine = BlueCloth.new(data, options)
      @output = nil
    end

    def evaluate(scope, locals, &block)
      @output ||= @engine.to_html
    end
  end

  # Maruku markdown implementation. See:
  # http://maruku.rubyforge.org/
  class MarukuTemplate < Template
    def self.engine_initialized?
      defined? ::Maruku
    end

    def initialize_engine
      require_template_library 'maruku'
    end

    def prepare
      @engine = Maruku.new(data, options)
      @output = nil
    end

    def evaluate(scope, locals, &block)
      @output ||= @engine.to_html
    end
  end

  # Kramdown Markdown implementation. See:
  # http://kramdown.rubyforge.org/
  class KramdownTemplate < Template
    DUMB_QUOTES = [39, 39, 34, 34]

    def self.engine_initialized?
      defined? ::Kramdown
    end

    def initialize_engine
      require_template_library 'kramdown'
    end

    def prepare
      options[:smart_quotes] = DUMB_QUOTES unless options[:smartypants]
      @engine = Kramdown::Document.new(data, options)
      @output = nil
    end

    def evaluate(scope, locals, &block)
      @output ||= @engine.to_html
    end
  end
end

