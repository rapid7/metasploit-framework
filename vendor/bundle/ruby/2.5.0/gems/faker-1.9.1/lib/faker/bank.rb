module Faker
  class Bank < Base
    flexible :bank

    class << self
      def account_number(digits = 11)
        rand.to_s[2..digits]
      end

      def iban(country_code = 'GB')
        # Each country has it's own format for bank accounts
        # Many of them use letters in certain parts of the account
        # Using regex patterns we can create virtually any type of bank account
        begin
          pattern = fetch("bank.iban_details.#{country_code.downcase}.bban_pattern")
        rescue I18n::MissingTranslationData
          raise ArgumentError, "Could not find iban details for #{country_code}"
        end

        # Use Faker::Base.regexify for creating a sample from bank account format regex
        account = Base.regexify(/#{pattern}/)

        # Add country code and checksum to the generated account to form valid IBAN
        country_code.upcase + iban_checksum(country_code, account) + account
      end

      def name
        fetch('bank.name')
      end

      def routing_number
        valid_routing_number
      end

      def routing_number_with_format
        compile_fraction(valid_routing_number)
      end

      def swift_bic
        fetch('bank.swift_bic')
      end

      private

      def checksum(num_string)
        num_array = num_string.split('').map(&:to_i)
        digit = (7 * (num_array[0] + num_array[3] + num_array[6]) + 3 * (num_array[1] + num_array[4] + num_array[7]) + 9 * (num_array[2] + num_array[5])) % 10
        digit == num_array[8]
      end

      def compile_routing_number
        digit_one_two = %w[00 01 02 03 04 05 06 07 08 09 10 11 12]
        ((21..32).to_a + (61..72).to_a + [80]).each { |x| digit_one_two << x.to_s }
        routing_num = digit_one_two.sample + rand_numstring + rand_numstring + rand_numstring + rand_numstring + rand_numstring + rand_numstring + rand_numstring
        routing_num
      end

      # Calculates the mandatory checksum in 3rd and 4th characters in IBAN format
      # source: https://en.wikipedia.org/wiki/International_Bank_Account_Number#Validating_the_IBAN
      def iban_checksum(country_code, account)
        # Converts letters to numbers according the iban rules, A=10..Z=35
        account_to_number = "#{account}#{country_code}00".upcase.chars.map do |d|
          d =~ /[A-Z]/ ? (d.ord - 55).to_s : d
        end.join.to_i

        # This is answer to (iban_to_num + checksum) % 97 == 1
        checksum = (1 - account_to_number) % 97

        # Use leftpad to make the size always to 2
        checksum.to_s.rjust(2, '0')
      end

      def valid_routing_number
        for _ in 0..50
          micr = compile_routing_number

          break if checksum(micr)
        end
        micr
      end

      def compile_fraction(routing_num)
        prefix = (1..50).to_a.map(&:to_s).sample
        numerator = routing_num.split('')[5..8].join.to_i.to_s
        denominator = routing_num.split('')[0..4].join.to_i.to_s
        prefix + '-' + numerator + '/' + denominator
      end

      def rand_numstring
        (0..9).to_a.map(&:to_s).sample
      end
    end
  end
end
