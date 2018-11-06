module Backports
  MOST_EXTREME_OBJECT_EVER = Object.new # :nodoc:
  class << MOST_EXTREME_OBJECT_EVER
    def <(whatever)
      true
    end

    def >(whatever)
      true
    end
  end
end
