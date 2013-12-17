# Prints validation errors recursively for this command and its {Metasploit::Framework::Command::Search::Table#visitor}.
module Metasploit::Framework::Command::Search::Table::ValidationErrors
  #
  # CONSTANTS
  #

  # Indentation for {#print_indented_error}
  INDENT = '  '

  #
  # Methods
  #

  protected

  def print_validation_errors
    super

    print_visitor_validation_errors(depth: 1)
  end

  private

  # Prints an error indented to :depth.
  #
  # @param message [String] message to print as an error.
  # @param options [Hash{Symbol => Integer}]
  # @option options [Integer] :depth (0) The depth of the error message.  0 depth means no indent.  Each level after
  #   0 is indented by {INDENT}.
  def print_indented_error(message, options={})
    options.assert_valid_keys(:depth)

    depth = options[:depth] || 0
    depth_indent = INDENT * depth

    print_error("#{depth_indent}#{message}")
  end

  # Prints validation errors for the operation at the given :depth.  Recursively prints the validation errors of any
  # children the operation may have.
  #
  # @param options (see #print_indented_error)
  # @option options (see #print_indented_error)
  # @return [void]
  def print_operation_validation_errors(operation, options={})
    options.assert_valid_keys(:depth)
    depth = options[:depth] || 0

    value = operation.value
    operator = operation.operator
    name = nil

    if operator
      name = operator.name
    end

    formatted_operation = "#{name}:#{value}"

    print_indented_validation_errors_with_context(
        operation,
        context: formatted_operation,
        depth: depth
    )

    if operator
      operator_depth = depth + 1
      print_indented_validation_errors_with_context(
          operator,
          context: name,
          depth: operator_depth
      )
    end

    if operation.respond_to? :children
      children_depth = depth + 1
      children = operation.children

      children.each do |child|
        print_operation_validation_errors(
            child,
            depth: children_depth
        )
      end
    end
  end

  # Prints validation errors for {Metasploit::Framework::Command::Search::Table#query} and for any operations on the
  # query.
  #
  # @param options (see #print_indented_error)
  # @option options (see #print_indented_error)
  # @return [void]
  def print_query_errors(options={})
    options.assert_valid_keys(:depth)
    depth = options[:depth] || 0

    query.errors.full_messages.each do |full_message|
      print_indented_error(full_message, depth: depth)
    end

    operations_depth = depth + 1

    query.operations.each do |operation|
      print_operation_validation_errors(operation, depth: operations_depth)
    end
  end

  # Prints validation errors for `model` prefixed by :context.
  #
  # @param options (see #print_indented_error)
  # @param options [Hash{Symbol => Integer,String}]
  # @option options [String] :context The context of this error.
  # @option options [Integer] :depth (0) The depth of the error message.  0 depth means no indent.  Each level after
  #   0 is indented by {INDENT}.
  # @raise [KeyError] if :context is not given
  # @return [void]
  def print_indented_validation_errors_with_context(model, options={})
    options.assert_valid_keys(:context, :depth)
    context = options.fetch(:context)
    depth = options[:depth] || 0

    model.errors.full_messages.each do |full_message|
      print_indented_error("#{context} - #{full_message}", depth: depth)
    end
  end

  # Prints validation errors for {Metasploit::Framework::Command::Search::Table#visitor} and its query.
  #
  # @param options (see #print_indented_error)
  # @option options (see #print_indented_error)
  # @return [void]
  def print_visitor_validation_errors(options={})
    options.assert_valid_keys(:depth)
    depth = options[:depth] || 0

    visitor.errors.full_messages.each do |full_message|
      print_indented_error(full_message, depth: depth)
    end

    query_depth = depth + 1
    print_query_errors(depth: query_depth)
  end
end
