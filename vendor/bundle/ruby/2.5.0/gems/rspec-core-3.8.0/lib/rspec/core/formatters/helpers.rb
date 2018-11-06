RSpec::Support.require_rspec_core "shell_escape"

module RSpec
  module Core
    module Formatters
      # Formatters helpers.
      module Helpers
        # @private
        SUB_SECOND_PRECISION = 5

        # @private
        DEFAULT_PRECISION = 2

        # @api private
        #
        # Formats seconds into a human-readable string.
        #
        # @param duration [Float, Fixnum] in seconds
        # @return [String] human-readable time
        #
        # @example
        #    format_duration(1) #=>  "1 minute 1 second"
        #    format_duration(135.14) #=> "2 minutes 15.14 seconds"
        def self.format_duration(duration)
          precision = case
                      when duration < 1 then    SUB_SECOND_PRECISION
                      when duration < 120 then  DEFAULT_PRECISION
                      when duration < 300 then  1
                      else                  0
                      end

          if duration > 60
            minutes = (duration.round / 60).to_i
            seconds = (duration - minutes * 60)

            "#{pluralize(minutes, 'minute')} #{pluralize(format_seconds(seconds, precision), 'second')}"
          else
            pluralize(format_seconds(duration, precision), 'second')
          end
        end

        # @api private
        #
        # Formats seconds to have 5 digits of precision with trailing zeros
        # removed if the number is less than 1 or with 2 digits of precision if
        # the number is greater than zero.
        #
        # @param float [Float]
        # @return [String] formatted float
        #
        # @example
        #    format_seconds(0.000006) #=> "0.00001"
        #    format_seconds(0.020000) #=> "0.02"
        #    format_seconds(1.00000000001) #=> "1"
        #
        # The precision used is set in {Helpers::SUB_SECOND_PRECISION} and
        # {Helpers::DEFAULT_PRECISION}.
        #
        # @see #strip_trailing_zeroes
        def self.format_seconds(float, precision=nil)
          return '0' if float < 0
          precision ||= (float < 1) ? SUB_SECOND_PRECISION : DEFAULT_PRECISION
          formatted = "%.#{precision}f" % float
          strip_trailing_zeroes(formatted)
        end

        # @api private
        #
        # Remove trailing zeros from a string.
        #
        # Only remove trailing zeros after a decimal place.
        # see: http://rubular.com/r/ojtTydOgpn
        #
        # @param string [String] string with trailing zeros
        # @return [String] string with trailing zeros removed
        def self.strip_trailing_zeroes(string)
          string.sub(/(?:(\..*[^0])0+|\.0+)$/, '\1')
        end
        private_class_method :strip_trailing_zeroes

        # @api private
        #
        # Pluralize a word based on a count.
        #
        # @param count [Fixnum] number of objects
        # @param string [String] word to be pluralized
        # @return [String] pluralized word
        def self.pluralize(count, string)
          "#{count} #{string}#{'s' unless count.to_f == 1}"
        end

        # @api private
        # Given a list of example ids, organizes them into a compact, ordered list.
        def self.organize_ids(ids)
          grouped = ids.inject(Hash.new { |h, k| h[k] = [] }) do |hash, id|
            file, id = Example.parse_id(id)
            hash[file] << id
            hash
          end

          grouped.sort_by(&:first).map do |file, grouped_ids|
            grouped_ids = grouped_ids.sort_by { |id| id.split(':').map(&:to_i) }
            id = Metadata.id_from(:rerun_file_path => file, :scoped_id => grouped_ids.join(','))
            ShellEscape.conditionally_quote(id)
          end
        end
      end
    end
  end
end
