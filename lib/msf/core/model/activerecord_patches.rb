#
# Patch object_from_yaml to load from Base64'd Marshal data
#
class ActiveRecord::Base
	def object_from_yaml(string)
		return string unless string.is_a?(String)
		return nil if not string
		return nil if string.empty?
		begin
			Marshal.load(string.unpack("m")[0])
		rescue ::Exception => e
			YAML.load(string)
		end
	end
end

#
# Patch the quote method to save serialized attributes as Base64'd Marshal data
#
module ActiveRecord
  module ConnectionAdapters # :nodoc:
    module Quoting
      # Quotes the column value to help prevent
      # {SQL injection attacks}[http://en.wikipedia.org/wiki/SQL_injection].
      def quote(value, column = nil)
        # records are quoted as their primary key
        return value.quoted_id if value.respond_to?(:quoted_id)

        case value
          when String, ActiveSupport::Multibyte::Chars
            value = value.to_s
            if column && column.type == :binary && column.class.respond_to?(:string_to_binary)
              "#{quoted_string_prefix}'#{quote_string(column.class.string_to_binary(value))}'" # ' (for ruby-mode)
            elsif column && [:integer, :float].include?(column.type)
              value = column.type == :integer ? value.to_i : value.to_f
              value.to_s
            else
              "#{quoted_string_prefix}'#{quote_string(value)}'" # ' (for ruby-mode)
            end
          when NilClass                 then "NULL"
          when TrueClass                then (column && column.type == :integer ? '1' : quoted_true)
          when FalseClass               then (column && column.type == :integer ? '0' : quoted_false)
          when Float, Fixnum, Bignum    then value.to_s
          # BigDecimals need to be output in a non-normalized form and quoted.
          when BigDecimal               then value.to_s('F')
          else
            if value.acts_like?(:date) || value.acts_like?(:time)
              "'#{quoted_date(value)}'"
            else
              "#{quoted_string_prefix}'#{quote_string([Marshal.dump(value)].pack("m"))}'"
            end
        end
      end
    end
  end
end

