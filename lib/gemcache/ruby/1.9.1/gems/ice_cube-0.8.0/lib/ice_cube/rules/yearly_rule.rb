module IceCube

  class YearlyRule < ValidatedRule

    include Validations::YearlyInterval

    def initialize(interval = 1)
      interval(interval)
      schedule_lock(:month, :day, :hour, :min, :sec)
    end

  end

end
