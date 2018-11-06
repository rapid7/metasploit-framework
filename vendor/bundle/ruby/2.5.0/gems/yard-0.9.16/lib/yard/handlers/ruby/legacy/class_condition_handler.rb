# frozen_string_literal: true
# (see Ruby::ClassConditionHandler)
# @since 0.5.4
class YARD::Handlers::Ruby::Legacy::ClassConditionHandler < YARD::Handlers::Ruby::Legacy::Base
  namespace_only
  handles TkIF, TkELSIF, TkUNLESS

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
  # @since 0.5.5
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
    case statement.tokens[1..-1].to_s.strip
    when /^(\d+)$/
      condition = $1 != "0"
    when /^defined\?\s*\(?\s*([A-Za-z0-9:_]+?)\s*\)?$/
      # defined? keyword used, let's see if we can look up the name
      # in the registry, then we'll try using Ruby's powers. eval() is not
      # *too* dangerous here since code is not actually executed.
      name = $1
      obj = YARD::Registry.resolve(namespace, name, true)
      begin
        condition = true if obj || Object.instance_eval("defined? #{name}")
      rescue SyntaxError, NameError
        condition = false
      end
    when "true"
      condition = true
    when "false"
      condition = false
    end

    if TkUNLESS === statement.tokens.first
      condition = !condition unless condition.nil?
    end
    condition
  end

  # @since 0.5.5
  def parse_then_block
    parse_block(:visibility => visibility)
  end

  # @since 0.5.5
  def parse_else_block
    return unless statement.block
    stmtlist = YARD::Parser::Ruby::Legacy::StatementList
    stmtlist.new(statement.block).each do |stmt|
      next unless TkELSE === stmt.tokens.first
      push_state(:visibility => visibility) do
        parser.process(stmtlist.new(stmt.block))
      end
    end
  end
end
