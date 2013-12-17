# An option argument for the `search` command in `msfconsole` that holds a column name, such as for `--display` or
# `--hide`.
class Metasploit::Framework::Command::Search::Argument::Column < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] value
  attr_accessor :value

  #
  # Validation Methods
  #

  def self.set
    unless instance_variable_defined? :@set
      # only operators directly on attributes or association attributes map to table_print's concept of chainable
      # columns
      @set = Mdm::Module::Instance.search_operator_by_name.each_with_object(Set.new) do |(name, operator), set|
        if operator.respond_to? :attribute
          column_name = operator.name.to_s
          set.add column_name
        end
      end
    end

    @set
  end

  #
  # Validations
  #

  validates :value,
            inclusion: {
                in: set
            }
end