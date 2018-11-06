# Defines common attributes and helpers for all importers.
module Metasploit::Credential::Importer::Base
  extend ActiveSupport::Concern

  #
  # Constants
  #

  # Whitelist of the {Metasploit::Credential::Private} subclass names allowed
  # in long-form CSV imports.
  LONG_FORM_ALLOWED_PRIVATE_TYPE_NAMES = [
      Metasploit::Credential::NonreplayableHash,
      Metasploit::Credential::NTLMHash,
      Metasploit::Credential::Password,
      Metasploit::Credential::PostgresMD5,
      Metasploit::Credential::SSHKey].map(&:name)


  # Whitelist of the {Metasploit::Credential::Private} subclass names allowed
  # in short-form CSV imports.
  SHORT_FORM_ALLOWED_PRIVATE_TYPE_NAMES = [
      Metasploit::Credential::NonreplayableHash,
      Metasploit::Credential::NTLMHash,
      Metasploit::Credential::Password,
      Metasploit::Credential::PostgresMD5].map(&:name)

  included do
    include ActiveModel::Validations

    # @!attribute filename
    #   The name of the file that is being imported
    #   @return [String]
    attr_accessor :filename

    # @!attribute input
    #   An {IO} that holds the import data. {File} in normal usage, {StringIO} in testing
    #   @return [IO]
    attr_accessor :input

    # @!attribute origin
    #   An {Metasploit::Credential::Origin} that represents the discrete
    #   importation of this set of credential objects
    #   @return [Metasploit::Credential::Origin::Import]
    attr_accessor :origin

    # @!attribute workspace
    #   The {Mdm::Workspace} that the credentials will be imported into
    #   @return[Mdm::Workspace]
    attr_accessor :workspace

    #
    # Validations
    #

    validates :origin, presence: true
    validates :input, presence: true
  end


  #
  # Instance Methods
  #

  # @param attributes [Hash{Symbol => String,nil}]
  def initialize(attributes={})
    attributes.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
  end
end
