module IceCube

  module Validations::DayOfWeek

    def day_of_week(dows)
      dows.each do |day, occs|
        occs.each do |occ|
          day = TimeUtil.symbol_to_day(day) if day.is_a?(Symbol)
          validations_for(:day_of_week) << Validation.new(day, occ)
        end
      end
      clobber_base_validations :day, :wday
      self
    end

    class Validation

      attr_reader :day, :occ

      StringBuilder.register_formatter(:day_of_week) do |segments|
        'on the ' + segments.join(' when it is the ')
      end

      def type
        :day
      end

      def build_s(builder)
        builder.piece(:day_of_week) << "#{StringBuilder.nice_number(occ)} #{Date::DAYNAMES[day]}"
      end

      def build_ical(builder)
        ical_day = IcalBuilder.fixnum_to_ical_day(day)
        # Delete any with this day and no occ first
        builder['BYDAY'].delete_if { |d| d == ical_day }
        builder['BYDAY'] << "#{occ}#{ical_day}"
      end

      def build_hash(builder)
        builder.validations[:day_of_week] ||= {}
        arr = (builder.validations[:day_of_week][day] ||= [])
        arr << occ
      end

      def initialize(day, occ)
        @day = day
        @occ = occ
      end

      def validate(time, schedule)
        # count the days to the weekday
        sum = day >= time.wday ? day - time.wday : 7 - time.wday + day
        wrapper = TimeUtil::TimeWrapper.new(time)
        wrapper.add :day, sum
        # and then count the week until a viable occ
        loop do
          which_occ, num_occ = TimeUtil.which_occurrence_in_month(wrapper.to_time, day)
          this_occ = occ < 0 ? num_occ + occ + 1 : occ
          break if which_occ == this_occ
          sum += 7
          wrapper.add :day, 7 # one week
        end
        sum
      end

    end

  end

end
