mydir = __dir__

begin
  require 'psych'
end

require 'i18n'
require 'set' # Fixes a bug in i18n 0.6.11

if I18n.respond_to?(:enforce_available_locales=)
  I18n.enforce_available_locales = true
end
I18n.load_path += Dir[File.join(mydir, 'locales', '**/*.yml')]
I18n.reload! if I18n.backend.initialized?

module Faker
  class Config
    @locale = nil
    @random = nil

    class << self
      attr_writer :locale
      attr_writer :random

      def locale
        @locale || I18n.locale
      end

      def own_locale
        @locale
      end

      def random
        @random || Random::DEFAULT
      end
    end
  end

  class Base
    Numbers = Array(0..9)
    ULetters = Array('A'..'Z')
    Letters = ULetters + Array('a'..'z')

    class << self
      ## by default numerify results do not start with a zero
      def numerify(number_string, leading_zero: false)
        return number_string.gsub(/#/) { rand(10).to_s } if leading_zero
        number_string.sub(/#/) { rand(1..9).to_s }.gsub(/#/) { rand(10).to_s }
      end

      def letterify(letter_string)
        letter_string.gsub(/\?/) { sample(ULetters) }
      end

      def bothify(string)
        letterify(numerify(string))
      end

      # Given a regular expression, attempt to generate a string
      # that would match it.  This is a rather simple implementation,
      # so don't be shocked if it blows up on you in a spectacular fashion.
      #
      # It does not handle ., *, unbounded ranges such as {1,},
      # extensions such as (?=), character classes, some abbreviations
      # for character classes, and nested parentheses.
      #
      # I told you it was simple. :) It's also probably dog-slow,
      # so you shouldn't use it.
      #
      # It will take a regex like this:
      #
      # /^[A-PR-UWYZ0-9][A-HK-Y0-9][AEHMNPRTVXY0-9]?[ABEHMNPRVWXY0-9]? {1,2}[0-9][ABD-HJLN-UW-Z]{2}$/
      #
      # and generate a string like this:
      #
      # "U3V  3TP"
      #
      def regexify(reg)
        reg = reg.source if reg.respond_to?(:source) # Handle either a Regexp or a String that looks like a Regexp
        reg
          .gsub(%r{^\/?\^?}, '').gsub(%r{\$?\/?$}, '') # Ditch the anchors
          .gsub(/\{(\d+)\}/, '{\1,\1}').gsub(/\?/, '{0,1}') # All {2} become {2,2} and ? become {0,1}
          .gsub(/(\[[^\]]+\])\{(\d+),(\d+)\}/) { |_match| Regexp.last_match(1) * sample(Array(Range.new(Regexp.last_match(2).to_i, Regexp.last_match(3).to_i))) }                # [12]{1,2} becomes [12] or [12][12]
          .gsub(/(\([^\)]+\))\{(\d+),(\d+)\}/) { |_match| Regexp.last_match(1) * sample(Array(Range.new(Regexp.last_match(2).to_i, Regexp.last_match(3).to_i))) }                # (12|34){1,2} becomes (12|34) or (12|34)(12|34)
          .gsub(/(\\?.)\{(\d+),(\d+)\}/) { |_match| Regexp.last_match(1) * sample(Array(Range.new(Regexp.last_match(2).to_i, Regexp.last_match(3).to_i))) }                      # A{1,2} becomes A or AA or \d{3} becomes \d\d\d
          .gsub(/\((.*?)\)/) { |match| sample(match.gsub(/[\(\)]/, '').split('|')) } # (this|that) becomes 'this' or 'that'
          .gsub(/\[([^\]]+)\]/) { |match| match.gsub(/(\w\-\w)/) { |range| sample(Array(Range.new(*range.split('-')))) } } # All A-Z inside of [] become C (or X, or whatever)
          .gsub(/\[([^\]]+)\]/) { |_match| sample(Regexp.last_match(1).split('')) } # All [ABC] become B (or A or C)
          .gsub('\d') { |_match| sample(Numbers) }
          .gsub('\w') { |_match| sample(Letters) }
      end

      # Helper for the common approach of grabbing a translation
      # with an array of values and selecting one of them.
      def fetch(key)
        fetched = sample(translate("faker.#{key}"))
        if fetched && fetched.match(%r{^\/}) && fetched.match(%r{\/$}) # A regex
          regexify(fetched)
        else
          fetched
        end
      end

      # Helper for the common approach of grabbing a translation
      # with an array of values and returning all of them.
      def fetch_all(key)
        fetched = translate("faker.#{key}")
        fetched = fetched.last if fetched.size <= 1
        if !fetched.respond_to?(:sample) && fetched.match(%r{^\/}) && fetched.match(%r{\/$}) # A regex
          regexify(fetched)
        else
          fetched
        end
      end

      # Load formatted strings from the locale, "parsing" them
      # into method calls that can be used to generate a
      # formatted translation: e.g., "#{first_name} #{last_name}".
      def parse(key)
        fetched = fetch(key)
        parts = fetched.scan(/(\(?)#\{([A-Za-z]+\.)?([^\}]+)\}([^#]+)?/).map do |prefix, kls, meth, etc|
          # If the token had a class Prefix (e.g., Name.first_name)
          # grab the constant, otherwise use self
          cls = kls ? Faker.const_get(kls.chop) : self

          # If an optional leading parentheses is not present, prefix.should == "", otherwise prefix.should == "("
          # In either case the information will be retained for reconstruction of the string.
          text = prefix

          # If the class has the method, call it, otherwise fetch the transation
          # (e.g., faker.phone_number.area_code)
          text += if cls.respond_to?(meth)
                    cls.send(meth)
                  else
                    # Do just enough snake casing to convert PhoneNumber to phone_number
                    key_path = cls.to_s.split('::').last.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
                    fetch("#{key_path}.#{meth.downcase}")
                  end

          # And tack on spaces, commas, etc. left over in the string
          text + etc.to_s
        end
        # If the fetched key couldn't be parsed, then fallback to numerify
        parts.any? ? parts.join : numerify(fetched)
      end

      # Call I18n.translate with our configured locale if no
      # locale is specified
      def translate(*args)
        opts = args.last.is_a?(Hash) ? args.pop : {}
        opts[:locale] ||= Faker::Config.locale
        opts[:raise] = true
        I18n.translate(*args.push(opts))
      rescue I18n::MissingTranslationData
        opts = args.last.is_a?(Hash) ? args.pop : {}
        opts[:locale] = :en

        # Super-simple fallback -- fallback to en if the
        # translation was missing.  If the translation isn't
        # in en either, then it will raise again.
        I18n.translate(*args.push(opts))
      end

      # Executes block with given locale set.
      def with_locale(tmp_locale = nil)
        current_locale = Faker::Config.own_locale
        Faker::Config.locale = tmp_locale
        I18n.with_locale(tmp_locale) { yield }
      ensure
        Faker::Config.locale = current_locale
      end

      def flexible(key)
        @flexible_key = key
      end

      # You can add whatever you want to the locale file, and it will get caught here.
      # E.g., in your locale file, create a
      #   name:
      #     girls_name: ["Alice", "Cheryl", "Tatiana"]
      # Then you can call Faker::Name.girls_name and it will act like #first_name
      def method_missing(mth, *args, &block)
        super unless @flexible_key

        if (translation = translate("faker.#{@flexible_key}.#{mth}"))
          sample(translation)
        else
          super
        end
      end

      def respond_to_missing?(method_name, include_private = false)
        super
      end

      # Generates a random value between the interval
      def rand_in_range(from, to)
        from, to = to, from if to < from
        rand(from..to)
      end

      def unique(max_retries = 10_000)
        @unique ||= UniqueGenerator.new(self, max_retries)
      end

      def sample(list)
        list.respond_to?(:sample) ? list.sample(random: Faker::Config.random) : list
      end

      def shuffle(list)
        list.shuffle(random: Faker::Config.random)
      end

      def rand(max = nil)
        if max.nil?
          Faker::Config.random.rand
        elsif max.is_a?(Range) || max.to_i > 0
          Faker::Config.random.rand(max)
        else
          0
        end
      end
    end
  end
end

Dir.glob(File.join(File.dirname(__FILE__), 'faker', '*.rb')).sort.each { |f| require f }

require 'extensions/array'
require 'extensions/symbol'

require 'helpers/char'
require 'helpers/unique_generator'
