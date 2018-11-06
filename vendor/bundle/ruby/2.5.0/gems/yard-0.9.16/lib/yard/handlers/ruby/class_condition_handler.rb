# frozen_string_literal: true
# Matches if/unless conditions inside classes and attempts to process only
# one branch (by evaluating the condition if possible).
#
# @example A simple class conditional
#   class Foo
#     if 0
#       # This method is ignored
#       def xyz; end
#     end
#   end
class YARD::Handlers::Ruby::ClassConditionHandler < YARD::Handlers::Ruby::Base
  handles meta_type(:condition)
  namespace_only

  process do
    condition = parse_condition
    if condition.nil?
      # Parse both blocks if we're unsure of the condition
      parse_then_block
      parse_else_block
    elsif condition
      parse_then_block
    else
      parse_else_block
    end
  end

  protected

  # Parses the condition part of the if/unless statement
  #
  # @return [true, false, nil] true if the condition can be definitely
  #   parsed to true, false if not, and nil if the condition cannot be
  #   parsed with certainty (it's dynamic)
  def parse_condition
    condition = nil

    # Right now we can handle very simple unary conditions like:
    #   if true
    #   if false
    #   if 0
    #   if 100 (not 0)
    #   if defined? SOME_CONSTANT
    #
    # The last case will do a lookup in the registry and then one
    # in the Ruby world (using eval).
    case statement.condition.type
    when :int
      condition = statement.condition[0] != "0"
    when :defined
      # defined? keyword used, let's see if we can look up the name
      # in the registry, then we'll try using Ruby's powers. eval() is not
      # *too* dangerous here since code is not actually executed.
      arg = statement.condition.first

      if arg.type == :var_ref
        name = arg.source
        obj = YARD::Registry.resolve(namespace, name, true)

        begin
          condition = true if obj || (name && Object.instance_eval("defined? #{name}"))
        rescue SyntaxError, NameError
          condition = false
        end
      end
    when :var_ref
      var = statement.condition[0]
      if var == s(:kw, "true")
        condition = true
      elsif var == s(:kw, "false")
        condition = false
      end
    end

    # Invert an unless condition
    if statement.type == :unless || statement.type == :unless_mod
      condition = !condition unless condition.nil?
    end
    condition
  end

  def parse_then_block
    parse_block(statement.then_block, :visibility => visibility)
  end

  def parse_else_block
    if statement.else_block
      parse_block(statement.else_block, :visibility => visibility)
    end
  end
end
