# A command that is a subcommand for a {Metasploit::Framework::Command::Parent}.
module Metasploit::Framework::Command::Child
  extend ActiveSupport::Concern

  included do
    include ActiveModel::Validations

    #
    # Validations
    #

    validates :parent,
              presence: true
  end

  #
  # Attributes
  #

  # @!attribute [rw] parent
  #   The parent command of which this command is a subcommand.
  #
  #   @return [Metasploit::Framework::Command::Parent]
  attr_accessor :parent

  #
  # Methods
  #

  delegate :dispatcher,
           :option_parser,
           :partial_word,
           :words,
           # must allow nil so that parent can be validated
           allow_nil: true,
           to: :parent
end