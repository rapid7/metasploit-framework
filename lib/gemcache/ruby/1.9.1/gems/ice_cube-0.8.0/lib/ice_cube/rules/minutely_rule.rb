module IceCube

  class MinutelyRule < ValidatedRule

    include Validations::MinutelyInterval

    def initialize(interval = 1)
      interval(interval)
      schedule_lock(:sec)
    end

  end

end
