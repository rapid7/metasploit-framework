module RKelly
  module JS
    class Boolean < Base
      class << self
        def create(*args)
          return false if args.length == 0
          self.new(args.first)
        end
      end
      def initialize(*args)
        super()
        value = args.first.nil? ? false : args.first
        self['valueOf'] = value
        self['valueOf'].function = lambda {
          value
        }
        self['toString'] = args.first.to_s
      end
    end
  end
end
