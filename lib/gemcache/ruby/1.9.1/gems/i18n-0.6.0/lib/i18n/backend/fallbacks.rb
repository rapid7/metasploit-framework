# I18n locale fallbacks are useful when you want your application to use
# translations from other locales when translations for the current locale are
# missing. E.g. you might want to use :en translations when translations in
# your applications main locale :de are missing.
#
# To enable locale fallbacks you can simply include the Fallbacks module to
# the Simple backend - or whatever other backend you are using:
#
#   I18n::Backend::Simple.include(I18n::Backend::Fallbacks)
module I18n
  @@fallbacks = nil

  class << self
    # Returns the current fallbacks implementation. Defaults to +I18n::Locale::Fallbacks+.
    def fallbacks
      @@fallbacks ||= I18n::Locale::Fallbacks.new
    end

    # Sets the current fallbacks implementation. Use this to set a different fallbacks implementation.
    def fallbacks=(fallbacks)
      @@fallbacks = fallbacks
    end
  end

  module Backend
    module Fallbacks
      # Overwrites the Base backend translate method so that it will try each
      # locale given by I18n.fallbacks for the given locale. E.g. for the
      # locale :"de-DE" it might try the locales :"de-DE", :de and :en
      # (depends on the fallbacks implementation) until it finds a result with
      # the given options. If it does not find any result for any of the
      # locales it will then throw MissingTranslation as usual.
      #
      # The default option takes precedence over fallback locales
      # only when it's a Symbol. When the default contains a String or a Proc
      # it is evaluated last after all the fallback locales have been tried.
      def translate(locale, key, options = {})
        return super if options[:fallback]
        default = extract_string_or_lambda_default!(options) if options[:default]

        options[:fallback] = true
        I18n.fallbacks[locale].each do |fallback|
          catch(:exception) do
            result = super(fallback, key, options)
            return result unless result.nil?
          end
        end
        options.delete(:fallback)

        return super(locale, nil, options.merge(:default => default)) if default
        throw(:exception, I18n::MissingTranslation.new(locale, key, options))
      end

      def extract_string_or_lambda_default!(options)
        defaults = [options[:default]].flatten
        if index = find_first_string_or_lambda_default(defaults)
          options[:default] = defaults[0, index]
          defaults[index]
        end
      end

      def find_first_string_or_lambda_default(defaults)
        defaults.each_with_index { |default, ix| return ix if String === default || Proc === default }
        nil
      end
    end
  end
end
