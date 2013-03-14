module Authlogic
  module I18n
    class Translator
      # If the I18n gem is present, calls +I18n.translate+ passing all 
      # arguments, else returns +options[:default]+.
      def translate(key, options = {})
        if defined?(::I18n)
          ::I18n.translate key, options
        else
          options[:default]
        end
      end
    end
  end
end
