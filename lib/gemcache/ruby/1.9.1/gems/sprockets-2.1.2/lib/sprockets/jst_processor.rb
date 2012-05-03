require 'tilt'

module Sprockets
  class JstProcessor < Tilt::Template
    def self.default_mime_type
      'application/javascript'
    end

    def self.default_namespace
      'this.JST'
    end

    def prepare
      @namespace = self.class.default_namespace
    end

    attr_reader :namespace

    def evaluate(scope, locals, &block)
      <<-JST
(function() {
  #{namespace} || (#{namespace} = {});
  #{namespace}[#{scope.logical_path.inspect}] = #{indent(data)};
}).call(this);
      JST
    end

    private
      def indent(string)
        string.gsub(/$(.)/m, "\\1  ").strip
      end
  end
end
