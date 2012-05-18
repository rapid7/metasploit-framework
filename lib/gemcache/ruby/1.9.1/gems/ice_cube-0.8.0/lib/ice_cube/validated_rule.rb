module IceCube

  class ValidatedRule < Rule

    include Validations::ScheduleLock

    include Validations::HourOfDay
    include Validations::MinuteOfHour
    include Validations::SecondOfMinute
    include Validations::DayOfMonth
    include Validations::DayOfWeek
    include Validations::Day
    include Validations::MonthOfYear
    include Validations::DayOfYear

    include Validations::Count
    include Validations::Until

    # Compute the next time after (or including) the specified time in respect
    # to the given schedule
    # NOTE: optimization target, sort the rules by their type, year first
    # so we can make bigger jumps more often
    def next_time(time, schedule, closing_time)
      loop do
        break if @validations.all? do |name, vals|
          # Execute each validation
          res = vals.map do |validation|
            validation.validate(time, schedule)
          end
          # If there is any nil, then we're set - otherwise choose the lowest
          if res.any? { |r| r.nil? || r == 0 }
            true
          else
            return nil if res.all? { |r| r === true } # allow quick escaping
            res.reject! { |r| r.nil? || r == 0 || r === true }
            if fwd = res.min
              type = vals.first.type # get the jump type
              dst_adjust = !vals.first.respond_to?(:dst_adjust?) || vals.first.dst_adjust?
              wrapper = TimeUtil::TimeWrapper.new(time, dst_adjust)
              wrapper.add(type, fwd)
              wrapper.clear_below(type)
              time = wrapper.to_time
            end
            false
          end
        end
        # Prevent a non-matching infinite loop
        return nil if closing_time && time > closing_time
      end
      # NOTE Uses may be 1 higher than proper here since end_time isn't validated
      # in this class.  This is okay now, since we never expose it - but if we ever
      # do - we should check that above this line, and return nil if end_time is past
      @uses += 1 if time
      time
    end 

    def to_s
      builder = StringBuilder.new
      @validations.each do |name, validations|
        validations.each do |validation|
          validation.build_s(builder)
        end
      end
      builder.to_s
    end

    def to_hash
      builder = HashBuilder.new(self)
      @validations.each do |name, validations|
        validations.each do |validation|
          validation.build_hash(builder)
        end
      end
      builder.to_hash
    end

    def to_ical
      builder = IcalBuilder.new
      @validations.each do |name, validations|
        validations.each do |validation|
          validation.build_ical(builder)
        end
      end
      builder.to_s
    end

    # Get the collection that contains validations of a certain type
    def validations_for(key)
      @validations ||= {}
      @validations[key] ||= []
    end

    # Fully replace validations
    def replace_validations_for(key, arr)
      @validations[key] = arr
    end

    # Remove the specified base validations
    def clobber_base_validations(*types)
      types.each do |type|
        @validations.delete(:"base_#{type}")
      end
    end

  end

end
