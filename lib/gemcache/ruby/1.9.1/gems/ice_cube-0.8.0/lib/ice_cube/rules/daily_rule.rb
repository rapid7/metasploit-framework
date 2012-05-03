module IceCube

  class DailyRule < ValidatedRule

    include Validations::DailyInterval

    def initialize(interval = 1)
      interval(interval)
      schedule_lock(:hour, :min, :sec)
    end

  end

end
