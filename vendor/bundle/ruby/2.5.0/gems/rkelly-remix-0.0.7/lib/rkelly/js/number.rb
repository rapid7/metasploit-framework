module RKelly
  module JS
    class Number < Base
      class << self
        def create(*args)
          self.new(args.first || 0)
        end
      end

      def initialize(value = 0)
        super()
        self['MAX_VALUE'] = 1.797693134862315e+308
        self['MIN_VALUE'] = 1.0e-306
        self['NaN']       = JS::NaN.new
        self['POSITIVE_INFINITY'] = 1.0/0.0
        self['NEGATIVE_INFINITY'] = -1.0/0.0
        self['valueOf'] = lambda { value }
        self['toString'] = value.to_s
      end
    end
  end
end
