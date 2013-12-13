module Metasploit::Framework::Command::Search::Table::TabCompletion
  #
  # Methods
  #

  def blank_tab_completions
    last_word = words.last

    if column_option_names.include? last_word
      completions = column_name_tab_completions(last_word)
    else
      # OptionParser.candidate won't return any candidates when last_word is nil or '', so pretend it's '-', which will
      # return all.
      completions = option_parser.candidate('-')

      completions += Mdm::Module::Instance.search_operator_by_name.keys.map(&:to_s)
    end

    completions
  end

  def partial_tab_completions
    operator = nil

    completions = option_parser.candidate(partial_word)

    # if not a partial option
    if completions.empty?
      last_word = words.last

      # partial column name
      if column_option_names.include? last_word
        completions = column_name_tab_completions(last_word)
      # partial operator/operation
      else
        # partial operation (full operator with missing or partial value for operation)
        if partial_word.include? ':'
          operation_or_operations = Metasploit::Model::Search::Operation.parse(
              formatted_operation: partial_word,
              query: query
          )
          operations = Array.wrap(operation_or_operations)

          if operations.length == 1
            operation = operations.first
            operator = operation.operator
          end
        # partial operator
        else
          operator_by_name = Mdm::Module::Instance.search_operator_by_name.select { |name, operator|
            name.to_s.start_with? partial_word
          }

          if operator_by_name.length == 1
            # if only one operator matches the partial operator then tab completion can jump ahead to tab completing
            # the operation with values.
            operator = operator_by_name.values.first
          else
            # if multiple matches then user input is needed to pick an operator before moving on to operation value
            # tab completion.
            completions = operator_by_name.keys.map(&:to_s)
          end
        end

        # tab completion can only be calculated on simple operators such as attribute and association operators as they
        # map directly to one column
        if operator && operator.respond_to?(:attribute)
          completions = operator_tab_completions(operator)
        end
      end
    end

    completions
  end

  private

  def column_name_tab_completions(last_word)
    column_name_set = Metasploit::Framework::Command::Search::Argument::Column.set

    #
    # remove columns already given
    #

    already_used_columns = []

    case last_word
      when '-d', '--display'
        already_used_columns = displayed_columns
      when '-D', '--hide'
        already_used_columns = hidden_columns
    end

    column_name_set -= already_used_columns.map(&:value)

    column_name_set.to_a
  end

  def column_option_names
    unless instance_variable_defined? :@column_option_names
      @column_option_names = []

      # have to send since visit is private
      option_parser.send(:visit, :each_option) { |option|
        if option.is_a?(OptionParser::Switch)
          argument = option.arg

          if argument && argument.include?('COLUMN')
            @column_option_names += option.short
            @column_option_names += option.long
          end
        end
      }
    end

    @column_option_names
  end

  def operator_tab_completions(operator)
    scope = nil
    query = self.query
    # cache validity so it doesn't have to be run again if visitor remains unfiltered
    visitor_valid = visitor.valid?

    if visitor_valid
      query = query.without_operator(operator)
      visitor = MetasploitDataModels::Search::Visitor::Relation.new(query: query)
      # filtered visitor can become invalid if operator was only operator in unfiltered query.
      visitor_valid = visitor.valid?
    end

    if visitor_valid
      scope = visitor.visit
    elsif query.operations.empty?
      scope = Mdm::Module::Instance.scoped
    end

    if scope
      completions = scope_tab_completions(operator: operator, scope: scope)
    else
      completions = nil
    end

    completions
  end

  def scope_tab_completions(options={})
    options.assert_valid_keys(:operator, :scope)
    operator = options.fetch(:operator)
    scope = options.fetch(:scope)

    join_visitor = MetasploitDataModels::Search::Visitor::Joins.new
    joins = join_visitor.visit(operator)
    scope = scope.joins(joins)

    attribute_visitor = MetasploitDataModels::Search::Visitor::Attribute.new
    attribute = attribute_visitor.visit operator

    # Exclude NULLS as the <formatted_operator>:<formatted_value> syntax doesn't support nil/NULLS (it would always be
    # treated as '')
    scope = scope.where(
        attribute.not_eq(nil)
    )

    # pluck doesn't take Arel::Attribute::Attributes and Arel::Attribute::Attributes doesn't have a #to_sql, so
    # have to to_sql it manually
    column_name = "#{attribute.relation.name}.#{attribute.name}"
    values = scope.uniq.pluck(column_name)

    values.collect { |value|
      escaped_value = Shellwords.escape(value)

      "#{operator.name}:#{escaped_value}"
    }
  end
end