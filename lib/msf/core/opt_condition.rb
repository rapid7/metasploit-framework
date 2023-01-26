# -*- coding: binary -*-

module Msf
  module OptCondition
    # Check a condition's result
    # @param [Msf::Module] mod The module module
    # @param [Msf::OptBase] opt the option which has conditions present
    # @return [String]
    def self.eval_condition(left_value, operator, right_value)
      case operator.to_sym
      when :==
        right_value == left_value
      when :!=
        right_value != left_value
      when :in
        right_value.include?(left_value)
      when :nin
        !right_value.include?(left_value)
      end
    end

    # Format an option's conditions as a human readable string
    # @param [Msf::Module] mod The module module
    # @param [Msf::OptBase] opt the option which has conditions present
    # @return [String]
    def self.format_conditions(_mod, opt)
      left_source = opt.conditions[0]
      operator = opt.conditions[1]
      right_value = opt.conditions[2]
      expects_blank_values = Array(right_value).all?(&:blank?)

      case operator.to_sym
      when :==
        "#{left_source} is #{right_value}"
      when :!=
        "#{left_source} is not #{right_value}"
      when :in
        if expects_blank_values
          return "#{left_source} is blank"
        end

        "#{left_source} is one of #{right_value.join(',')}"
      when :nin
        if expects_blank_values
          return "#{left_source} is not blank"
        end

        "#{left_source} not in #{right_value.join(',')}"
      else
        "#{left_source} #{operator} #{right_value}"
      end
    end

    # Check an OPTION conditions. This function supports
    # dump_options()
    def self.show_option(mod, opt)
      return true if opt.conditions.empty?

      left_source = opt.conditions[0]
      operator = opt.conditions[1]
      right_value = opt.conditions[2]
      if left_source == 'ACTION'
        left_value = mod.action ? mod.action.name.to_s : nil
      elsif left_source == 'TARGET'
        left_value = mod.target.name.to_s
      else
        left_value = mod.datastore[left_source] || opt.default
      end

      show = eval_condition(left_value, operator, right_value)
      show ||= eval_condition(left_value.to_s, operator, right_value) if left_value.is_a?(Symbol)
      show
    end
  end
end
