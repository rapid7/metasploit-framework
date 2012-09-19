module IceCube

  class MonthlyRule < ValidatedRule

    include Validations::MonthlyInterval

    def initialize(interval = 1)
      interval(interval)
      schedule_lock(:day, :hour, :min, :sec)
    end

  end

end
