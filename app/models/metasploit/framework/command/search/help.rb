class Metasploit::Framework::Command::Search::Help < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Child

  protected

  def run_with_valid
    print option_parser.help
    print_line
    operators
    print_line
    examples
  end

  private

  def column_operators(operators)
    print_line 'Columns/Operators:'

    # treat the associations as a tree structure
    sorted_column_operators = operators.sort_by { |operator|
      if operator.respond_to? :association
        [operator.association, operator.attribute.to_s]
      else
        [:'', operator.attribute.to_s]
      end
    }

    print_operators(sorted_column_operators)
  end

  def default_example
    print_line '  # All post modules for Windows'
    print_line '  > search module_class.module_type:post platforms.fully_qualified_name:Windows'
    print_line '  MODULE_CLASS.FULL_NAME             | MODULE_CLASS.MODULE_TYPE | RANK.NAME | PLATFORMS.FULLY_QUALIFIED_NAME'
    print_line '  -----------------------------------|--------------------------|-----------|-------------------------------'
    print_line '  post/multi/gather/apple_ios_backup | post                     | Normal    | Windows'
  end

  def display_example
    print_line '  # All post module for Windows with the author names'
    print_line '  > search --display authors.name module_class.module_type:post platforms.fully_qualified_name:Windows'
    print_line '  MODULE_CLASS.FULL_NAME             | MODULE_CLASS.MODULE_TYPE | RANK.NAME | AUTHORS.NAME | PLATFORMS.FULLY_QUALIFIED_NAME'
    print_line '  -----------------------------------|--------------------------|-----------|--------------|-------------------------------'
    print_line '  post/multi/gather/apple_ios_backup | post                     | Normal    | bannedit     | Windows'
    print_line '                                     |                          |           | hdm          |'
  end

  def examples
    print_line 'Examples:'
    print_line

    default_example
    print_line

    hide_example
    print_line

    display_example
  end

  def hide_example
    print_line '  # All post modules for Windows without showing the platform'
    print_line '  > search --hide platforms.fully_qualified_name module_class.module_type:post platforms.fully_qualified_name:Windows'
    print_line '  MODULE_CLASS.FULL_NAME             | MODULE_CLASS.MODULE_TYPE | RANK.NAME'
    print_line '  -----------------------------------|--------------------------|----------'
    print_line '  post/multi/gather/apple_ios_backup | post                     | Normal'
  end

  def operators
    column_operators, only_operators = Mdm::Module::Instance.search_operator_by_name.values.partition { |operator|
      operator.respond_to? :attribute
    }

    column_operators(column_operators)
    print_line
    operators_only(only_operators)
  end

  def operators_only(operators)
    print_line 'Operators Only:'

    sorted_only_operators = operators.sort_by(&:name)

    print_operators(sorted_only_operators)
  end

  def print_operators(operators)
    operators.each do |operator|
      print_line "  #{operator.name}"
      print_line "    #{operator.help}"
    end
  end
end