module Formtastic
  module Inputs
    # Outputs a series of select boxes for the fragments that make up a time (hour, minute, second).
    # Unless `:ignore_date` is true, it will render hidden inputs for the year, month and day as 
    # well, defaulting to `Time.current` if the form object doesn't have a value, much like Rails' 
    # own `time_select`.
    #
    # @see Formtastic::Inputs::Base::Timeish Timeish module for documentation of date, time and datetime input options.
    class TimeInput 
      include Base
      include Base::Timeish
      
      # we don't want year / month / day fragments if :ignore_date => true
      def fragments
        time_fragments
      end
      
      def fragment_value(fragment)
        value ? value.send(fragment) : ""
      end
      
      def hidden_fragments
        if !options[:ignore_date]
          date_fragments.map do |fragment|
            template.hidden_field_tag(hidden_field_name(fragment), fragment_value(fragment), :id => fragment_id(fragment), :disabled => input_html_options[:disabled] )
          end.join.html_safe
        else
          super
        end
      end
      
    end
  end
end
