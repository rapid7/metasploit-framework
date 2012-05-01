module IceCube

  class HourlyRule < ValidatedRule

    include Validations::HourlyInterval

    def initialize(interval = 1)
      interval(interval)
      schedule_lock(:min, :sec)
    end

  end

end
