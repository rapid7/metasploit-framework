module Metasploit::Framework::Command::Search::Table::Columns
  extend ActiveSupport::Concern

  #
  # CONSTANTS
  #

  DEFAULT_COLUMN_NAMES = [
      'module_class.full_name',
      'rank.name'
  ]

  included do
    include ActiveModel::Validations

    #
    # Validations
    #
    validates :column_name_set,
              presence: true
  end

  #
  # Instance Methods
  #

  def column_name_set
    displayed_column_name_set + query_column_name_set - hidden_column_name_set
  end

  def displayed_columns
    @display_columns ||= DEFAULT_COLUMN_NAMES.collect { |column_name|
      Metasploit::Framework::Command::Search::Argument::Column.new(
          value: column_name
      )
    }
  end

  def hidden_columns
    @hidden_columns ||= []
  end

  private

  def displayed_column_name_set
    Set.new displayed_columns.map(&:value)
  end

  def hidden_column_name_set
    Set.new hidden_columns.map(&:value)
  end

  def query_column_name_set
    @query_column_name_set ||= query.operations.each_with_object(Set.new) do |operation, set|
      operator_name = operation.operator.name.to_s

      if Metasploit::Framework::Command::Search::Argument::Column.set.include? operator_name
        set.add operator_name
      end
    end
  end
end
