module RKelly
  module JS
    class Math < Base
      def initialize
        super
        self['PI'] = ::Math::PI
      end
    end
  end
end
