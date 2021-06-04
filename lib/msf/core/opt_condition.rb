# -*- coding: binary -*-
module Msf
  module OptCondition

    # Check a condition's result
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
