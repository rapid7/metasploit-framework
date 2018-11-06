# Search the equivalent of the text fields from `Mdm::Module::Detail` and its associations, making a union of
# `description`, `name`, `actions.name`, `architectures.abbreviation`, `platform`, and `ref`.
class Metasploit::Model::Search::Operator::Deprecated::Text < Metasploit::Model::Search::Operator::Group::Union
  #
  # CONSTANTS
  #

  # Names of operators that are unioned together for {Metasploit::Model::Search::Operator::Group::Union#operate_on}.
  OPERATOR_NAMES = [
      'description',
      'name',
      'actions.name',
      'architectures.abbreviation',
      # platforms.name or targets.name
      'platform',
      # authors.name, references.designation, or references.url are handled by
      # {Metasploit::Model::Search::Operator::Deprecated::Ref} to reuse its special parsing of the old
      # <abbreviation OR 'URL'>-<designation or url> format.
      'ref',
  ]

  # `description`, `name`, `actions.name`, `architectures.abbreviation`, `platform`, and `ref`.
  #
  # @param formatted_value [String] value parsed from formatted operation
  # @return [Array<Metasploit::Model::Search::Operation::Base>]
  def children(formatted_value)
    OPERATOR_NAMES.collect { |operator_name|
      named_operator = operator(operator_name)
      named_operator.operate_on(formatted_value)
    }
  end
end
