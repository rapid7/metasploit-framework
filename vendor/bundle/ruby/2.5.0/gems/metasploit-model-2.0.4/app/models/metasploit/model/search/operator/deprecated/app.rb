# Emulates the deprecated `app` operator by converting it to the union of `authors.name:<value>`,
# `email_addresses.local<value before '@'>`, and `email_addresses.domain:<value before '@'>` in {#operate_on}.
class Metasploit::Model::Search::Operator::Deprecated::App < Metasploit::Model::Search::Operator::Delegation
  #
  # CONSTANTS
  #

  # Maps values passed to deprecated `app` operator to the equivalent value for the `stance` operator.
  STANCE_BY_APP = {
      'client' => 'passive',
      'server' => 'aggressive'
  }

  #
  # Methods
  #

  # Converts `app:client` to `stance:passive` and `app:server` to `stance:aggressive`.
  #
  # @return [Metasploit::Model::Search::Operation::Base]
  def operate_on(formatted_value)
    stance_value = STANCE_BY_APP[formatted_value]
    stance_operator = operator('stance')

    stance_operator.operate_on(stance_value)
  end
end