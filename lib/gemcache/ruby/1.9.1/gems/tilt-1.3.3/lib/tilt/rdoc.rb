require 'tilt/template'

module Tilt
  # RDoc template. See:
  # http://rdoc.rubyforge.org/
  #
  # It's suggested that your program require 'rdoc/markup' and
  # 'rdoc/markup/to_html' at load time when using this template
  # engine.
  class RDocTemplate < Template
    self.default_mime_type = 'text/html'

    def self.engine_initialized?
      defined? ::RDoc::Markup
    end

    def initialize_engine
      require_template_library 'rdoc/markup'
      require_template_library 'rdoc/markup/to_html'
    end

    def prepare
      markup = RDoc::Markup::ToHtml.new
      @engine = markup.convert(data)
      @output = nil
    end

    def evaluate(scope, locals, &block)
      @output ||= @engine.to_s
    end
  end
end
