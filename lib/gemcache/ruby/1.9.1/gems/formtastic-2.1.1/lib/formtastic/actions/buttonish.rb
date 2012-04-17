module Formtastic
  module Actions
    module Buttonish
      
      def supported_methods
        [:submit, :reset]
      end

      def extra_button_html_options
        {
          :type => method
        }
      end
      
    end
  end
end