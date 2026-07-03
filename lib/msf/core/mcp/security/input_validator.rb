# frozen_string_literal: true

require 'ipaddr'

module Msf::MCP
  module Security
    class InputValidator
      LIMIT_DEFAULT = 100
      LIMIT_MIN = 1
      LIMIT_MAX = 1000

      # Generic parameter validation against a constraint
      #
      # Dispatches based on the constraint type:
      # - Array  → value must be included in the list (enum)
      # - Range  → value must be an integer within the range, or a Range whose
      #            bounds are within the constraint (range must be integer-bounded)
      # - Regexp → value (via .to_s) must match the pattern
      #
      # @param name [String] Parameter name (used in error messages)
      # @param value [Object] Value to validate
      # @param constraint [Array, Range, Regexp] Allowed values, range, or pattern
      # @param allow_nil [Boolean] Whether nil/empty values are allowed (default: false)
      # @param max_size [Integer] (optional) Maximum length for string values (only applies to Regexp constraints)
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_parameter!(name, value, constraint, allow_nil: false, max_size: nil)
        if allow_nil
          return true if value.nil?
          return true if value.respond_to?(:empty?) && value.empty?
        else
          raise ValidationError, "#{name} cannot be nil" if value.nil?
          raise ValidationError, "#{name} cannot be empty" if value.respond_to?(:empty?) && value.empty?
        end

        case constraint
        when Array
          unless constraint.include?(value)
            raise ValidationError, "Invalid #{name}: #{value.inspect}. Must be one of: #{constraint.join(', ')}"
          end
        when Range
          unless constraint.first.is_a?(Integer) && constraint.last.is_a?(Integer)
            raise ArgumentError, "Range constraint must be a range of integers, got #{constraint.first.class}..#{constraint.last.class}"
          end
          if value.is_a?(Range)
            begin
              int_first = Integer(value.first)
              int_last = Integer(value.last)
            rescue TypeError, ArgumentError
              raise ValidationError, "#{name} must have integer bounds: #{value.inspect}"
            end
            unless constraint.cover?(int_first..int_last)
              raise ValidationError, "#{name} must be between #{constraint.min} and #{constraint.max}: #{int_first}..#{int_last}"
            end
          else
            begin
              int_value = Integer(value)
            rescue TypeError, ArgumentError
              raise ValidationError, "#{name} must be an integer: #{value.inspect}"
            end
            unless constraint.cover?(int_value)
              raise ValidationError, "#{name} must be between #{constraint.min} and #{constraint.max}: #{value}"
            end
          end
        when Regexp
          string_value = value.to_s
          if max_size && string_value.length > max_size
            raise ValidationError, "#{name} too long (max #{max_size} characters)"
          end
          unless string_value.match?(constraint)
            raise ValidationError, "Invalid #{name} format: #{value}"
          end
        else
          raise ArgumentError, "Unsupported constraint type: #{constraint.class}"
        end

        true
      end

      # Validate IP address or CIDR range
      #
      # @param addr [String] IP address or CIDR (e.g., "192.168.1.1" or "192.168.1.0/24")
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_ip_address!(addr)
        return true if addr.nil? || addr.empty?

        begin
          IPAddr.new(addr)
          true
        rescue IPAddr::InvalidAddressError
          raise ValidationError, "Invalid IP address or CIDR: #{addr}"
        end
      end

      # Validate port or port range
      #
      # @param range [String, Integer] Port number or range (e.g., "80" or "80-443")
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_port_range!(range)
        return true if range.nil? || range.to_s.empty?

        range_str = range.to_s

        # Match a port range like "80-443" — requires digits on both sides of the dash
        if range_str.match?(/\A\s*[[:alnum:]]+-[[:alnum:]]+\s*\z/)
          begin
            start_port, end_port = range_str.split('-', 2).map { |p| Integer(p.strip) }
          rescue TypeError, ArgumentError
            raise ValidationError, "Port range must have integer bounds: #{range_str}"
          end
          validate_parameter!('Port range', start_port..end_port, 1..65535)
        else
          validate_parameter!('Port', range_str, 1..65535)
        end

        true
      end

      # Validate query string for module search
      #
      # @param query [String] Search query
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_search_query!(query)
        validate_parameter!('Search query', query, /\A[[:print:]]+\z/, allow_nil: false, max_size: 500)
      end

      # Validate limit parameter for pagination
      #
      # @param limit [Integer] Limit value
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_limit!(limit)
        validate_parameter!('Limit', limit, LIMIT_MIN..LIMIT_MAX, allow_nil: true)
      end

      # Validate offset parameter for pagination
      #
      # @param offset [Integer] Offset value
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_offset!(offset)
        validate_parameter!('Offset', offset, 0..LIMIT_MAX, allow_nil: true)
      end

      # Validate pagination parameters
      #
      # @param limit [Integer] Limit value
      # @param offset [Integer] Offset value
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_pagination!(limit, offset)
        validate_limit!(limit)
        validate_offset!(offset)
      end

      # Validate module type
      #
      # @param module_type [String] Module type
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_module_type!(module_type)
        validate_parameter!('Module type', module_type, %w[exploit auxiliary post payload encoder evasion nop])
      end

      # Validate module name
      #
      # @param module_name [String] Module name/path
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_module_name!(module_name)
        # Basic path validation (alphanumeric, slashes, underscores, hyphens)
        validate_parameter!('Module name', module_name, %r{\A[\w/\-]+\z}, max_size: 500)
      end

      # Validate only_up boolean parameter
      #
      # @param only_up [Boolean] Only up parameter
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_only_up!(only_up)
        validate_parameter!('only_up', only_up, [true, false])
      end

      # Validate protocol parameter
      #
      # @param protocol [String] Protocol ('tcp' or 'udp')
      # @return [true] If valid
      # @raise [ValidationError] If invalid
      def self.validate_protocol!(protocol)
        validate_parameter!('Protocol', protocol.to_s.downcase, %w[tcp udp], allow_nil: true)
      end
    end
  end
end
