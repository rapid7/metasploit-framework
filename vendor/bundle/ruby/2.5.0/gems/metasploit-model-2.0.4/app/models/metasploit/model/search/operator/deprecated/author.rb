# Operator that emulates the behavior of 'author' operator that could search `Mdm::Module::Detail` by making
# {Metasploit::Model::Search::Operation::Group::Union} between `authors.name`, `email_addresss.domain`, and
# `email_addresses.local`.
class Metasploit::Model::Search::Operator::Deprecated::Author < Metasploit::Model::Search::Operator::Group::Union
  # Turns author:<formatted_value> into Array of authors.name:<formatted_value>,
  # email_addresses.domain:<formatted_value>, and email_addresses.local:<formatted_value> operations.  If there is an
  # '@' in `formatted_value`, then the portion of `formatted_value` before the '@' is used for `email_addresses.local`
  # and the portion of `formatted_value` after the '@' is used for `email_addresses.domain`.
  #
  # @param formatted_value [String] value after ':' in formatted operation.
  # @return [Array<Metasploit::Model::Search::Operation::Base>]
  def children(formatted_value)
    operations = []

    authors_name_operator = operator('authors.name')
    operations << authors_name_operator.operate_on(formatted_value)

    if formatted_value.include? '@'
      local, domain = formatted_value.split('@', 2)
    else
      domain = formatted_value
      local = formatted_value
    end

    email_address_domain_operator = operator('email_addresses.domain')
    operations << email_address_domain_operator.operate_on(domain)

    email_addresses_local_operator = operator('email_addresses.local')
    operations << email_addresses_local_operator.operate_on(local)

    operations
  end
end