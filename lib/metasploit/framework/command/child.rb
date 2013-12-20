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
           # must allow nil so that parent can be validated
           allow_nil: true,
           to: :parent

  # Words from {#parent}.
  #
  # @return [Array<String>] from {#parent}
  # @return [[]] if {#parent} is nil
  def words
    unless parent.nil?
      parent.words
    else
      []
    end
  end
end