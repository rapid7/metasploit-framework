module Formtastic
  module Inputs

    # Outputs a series of select boxes for the fragments that make up a date and time (year, month, day, hour, minute, second).
    #
    # @see Formtastic::Inputs::Base::Timeish Timeish module for documentation of date, time and datetime input options.
    class DatetimeInput 
      include Base
      include Base::Timeish
    end
  end
end