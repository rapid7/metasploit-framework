module RKelly
  module JS
    class Array < Base
      class << self
        def create(*args)
          self.new(*args)
        end
      end

      def initialize(*args)
        super()
      end
    end
  end
end
