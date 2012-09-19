require 'tilt/template'

module Tilt
  # Markaby
  # http://github.com/markaby/markaby
  class MarkabyTemplate < Template
    def self.builder_class
      @builder_class ||= Class.new(Markaby::Builder) do
        def __capture_markaby_tilt__(&block)
          __run_markaby_tilt__ do
            text capture(&block)
          end
        end
      end
    end

    def self.engine_initialized?
      defined? ::Markaby
    end

    def initialize_engine
      require_template_library 'markaby'
    end

    def prepare
    end

    def evaluate(scope, locals, &block)
      builder = self.class.builder_class.new({}, scope)
      builder.locals = locals

      if data.kind_of? Proc
        (class << builder; self end).send(:define_method, :__run_markaby_tilt__, &data)
      else
        builder.instance_eval <<-CODE, __FILE__, __LINE__
          def __run_markaby_tilt__
            #{data}
          end
        CODE
      end

      if block
        builder.__capture_markaby_tilt__(&block)
      else
        builder.__run_markaby_tilt__
      end

      builder.to_s
    end
  end
end

