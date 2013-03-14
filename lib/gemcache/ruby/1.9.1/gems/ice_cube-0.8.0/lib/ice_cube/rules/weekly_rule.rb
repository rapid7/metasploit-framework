module IceCube

  class WeeklyRule < ValidatedRule

    include Validations::WeeklyInterval

    def initialize(interval = 1, week_start = :sunday)
      interval(interval, week_start)
      schedule_lock(:wday, :hour, :min, :sec)
    end

  end

end
