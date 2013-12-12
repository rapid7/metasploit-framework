module Metasploit::Framework::Command::Search::Table::ValidationErrors
  protected

  def print_validation_errors
    super

    print_visitor_validation_errors
  end

  private

  def print_operation_validation_errors(operation)
    value = operation.value
    operator = operation.operator
    name = nil

    if operator
      name = operator.name
    end

    formatted_operation = "#{name}:#{value}"

    print_validation_errors_with_context(operation, formatted_operation)

    if operator
      print_validation_errors_with_context(operator, name)
    end
  end

  def print_query_errors
    query.errors.full_messages.each do |full_message|
      print_error(full_message)
    end

    query.operations.each do |operation|
      print_operation_validation_errors(operation)
    end
  end

  def print_validation_errors_with_context(model, context)
    model.errors.full_messages.each do |full_message|
      print_error("#{context} - #{full_message}")
    end
  end

  def print_visitor_validation_errors
    visitor.errors.full_messages.each do |full_message|
      print_error(full_message)
    end

    print_query_errors
  end
end
