module IceCube

  module Validations::ScheduleLock

    # Lock the given times down the schedule's start_time for that position
    # These locks are all clobberable by other rules of the same #type
    # using clobber_base_validation
    def schedule_lock(*types)
      types.each do |type|
        validations_for(:"base_#{type}") << Validation.new(type)
      end
    end

    # A validation used for locking time into a certain value
    class Validation

      include Validations::Lock

      attr_reader :type, :value

      def initialize(type)
        @type = type
      end

      # no -op
      def build_s(builder)
      end

      # no -op
      def build_ical(builder)
      end

      # no -op
      def build_hash(builder)
      end

    end

  end

end
