# Groups together {Metasploit::Model::Search::Operation::Base operations} and/or or nested groups.
class Metasploit::Model::Search::Group::Base < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] children
  #   {Metasploit::Model::Search::Operation::Base Operations} or nested {Metasploit::Model::Search::Group::Base groups}.
  #
  #   @return [Array<Metasploit::Model::Search::Group::Base, Metasploit::Model::Search::Operation::Base>]
  attr_accessor :children

  #
  # Validations
  #

  validates :children,
            :length => {
                :minimum => 1
            }
end