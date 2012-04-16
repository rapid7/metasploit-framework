require 'tilt/template'

module Tilt
  # RedCloth implementation. See:
  # http://redcloth.org/
  class RedClothTemplate < Template
    def self.engine_initialized?
      defined? ::RedCloth
    end

    def initialize_engine
      require_template_library 'redcloth'
    end

    def prepare
      @engine = RedCloth.new(data)
      @output = nil
    end

    def evaluate(scope, locals, &block)
      @output ||= @engine.to_html
    end
  end
end

