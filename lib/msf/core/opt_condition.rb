# -*- coding: binary -*-

module Msf
  module OptCondition
    # Evaluate a single condition or a compound condition
    # @param [Msf::Module] mod The module instance
    # @param [String] condition The condition string (e.g., "UPDATE_UPN == true && SMBUsername.nil?")
    # @return [Boolean]
    def self.eval_condition(mod, condition)

      tokens = condition.split(/(&&|\|\|)/).map(&:strip)

      result = nil
      operator = nil

      tokens.each do |token|
        if token == '&&' || token == '||'
          operator = token
        else
          left_source, operator_symbol, right_value = parse_condition(token)
          left_value = fetch_value(mod, left_source)
          current_result = eval_single_condition(left_value, operator_symbol, right_value)

          if result.nil?
            result = current_result
          elsif operator == '&&'
            result &&= current_result
          elsif operator == '||'
            result ||= current_result
          end
        end
      end

      result
    end

    # Parse a single condition string into components
    # @param [String] condition The condition string (e.g., "UPDATE_UPN == true")
    # @return [Array] [left_source, operator, right_value]
    def self.parse_condition(condition)
      match = condition.match(/(.+?)\s*(==|!=|\.nil\?)\s*(.+)?/)
      raise ArgumentError, "Invalid condition: #{condition}" unless match

      left_source = match[1].strip
      operator = match[2].strip
      right_value = match[3]&.strip

      [left_source, operator, right_value]
    end

    # Fetch the value of a datastore option or default
    # @param [Msf::Module] mod The module instance
    # @param [String] source The source key (e.g., "UPDATE_UPN")
    # @return [Object] The value of the source
    def self.fetch_value(mod, source)
      if source == 'ACTION'
        mod.action ? mod.action.name.to_s : nil
      elsif source == 'TARGET'
        mod.target.name.to_s
      else
        mod.datastore[source] || nil
      end
    end

    # Evaluate a single condition
    # @param [Object] left_value The left-hand value
    # @param [String] operator The operator (e.g., "==", "!=")
    # @param [Object] right_value The right-hand value
    # @return [Boolean]
    def self.eval_single_condition(left_value, operator, right_value)
      case operator
      when '=='
        left_value.to_s == right_value
      when '!='
        left_value.to_s != right_value
      when '.nil?'
        left_value.nil?
      else
        raise ArgumentError, "Invalid operator: #{operator}"
      end
    end

    # Check if an option should be shown based on its conditions
    # @param [Msf::Module] mod The module instance
    # @param [Msf::OptBase] opt The option to check
    # @return [Boolean]
    def self.show_option(mod, opt)
      return true if opt.conditions.empty?

      condition = opt.conditions.join(' ')
      eval_condition(mod, condition)
    end


    # Format conditions for display
    # @param [Array] conditions The list of conditions
    # @param [Msf::Module] mod (optional) The module instance (if passed)
    # @return [String] The formatted conditions string
    def self.format_conditions(conditions, mod = nil)

      return '' unless conditions.is_a?(Array) && !conditions.empty?

      conditions.join(' ')
    end
  end
end