# This mixin is intended to provide all of the common validations sued by {Metasploit::Credential::Core} and anything
# that mimics it's behaviour by tying together {Metasploit::Credential::Public}, {Metasploit::Credential::Private},
# and {Metasploit::Credential::Realm} objects.
module Metasploit::Credential::CoreValidations
  extend ActiveSupport::Concern

  included do

    validate :minimum_presence
    validate :public_for_ssh_key

    #
    # Attribute Validations
    #


    # replicates 'unique_private_metasploit_credential_cores' index
    validates :private_id,
              uniqueness: {
                  message: 'is already taken for credential cores with only a private credential',
                  scope: [
                      :workspace_id,
                      # realm_id and public_id need to be included in scope so validator uses IS NULL.
                      :realm_id,
                      :public_id
                  ]
              },
              if: '!realm.present? && !public.present? && private.present?'
    # replicates 'unique_public_metasploit_credential_cores' index
    validates :public_id,
              uniqueness: {
                  message: 'is already taken for credential cores with only a public credential',
                  scope: [
                      :workspace_id,
                      # realm_id and private_id need to be included in scope so validator uses IS NULL.
                      :realm_id,
                      :private_id
                  ]
              },
              if: '!realm.present? && public.present? && !private.present?'
    # replicates 'unique_realmless_metasploit_credential_cores' index
    validates :private_id,
              uniqueness: {
                  message: 'is already taken for credential cores without a credential realm',
                  scope: [
                      :workspace_id,
                      # realm_id needs to be included in scope so validator uses IS NULL.
                      :realm_id,
                      :public_id
                  ]
              },
              if: '!realm.present? && public.present? && private.present?'
    # replicates 'unique_publicless_metasploit_credential_cores' index
    validates :private_id,
              uniqueness: {
                  message: 'is already taken for credential cores without a public credential',
                  scope: [
                      :workspace_id,
                      :realm_id,
                      # public_id needs to be included in scope so validator uses IS NULL.
                      :public_id
                  ]
              },
              if: 'realm.present? && !public.present? && private.present?'
    # replicates 'unique_privateless_metasploit_credential_cores' index
    validates :public_id,
              uniqueness: {
                  message: 'is already taken for credential cores without a private credential',
                  scope: [
                      :workspace_id,
                      :realm_id,
                      # private_id needs to be included in scope so validator uses IS NULL.
                      :private_id
                  ]
              },
              if: 'realm.present? && public.present? && !private.present?'
    # replicates 'unique_complete_metasploit_credential_cores' index
    validates :private_id,
              uniqueness: {
                  message: 'is already taken for complete credential cores',
                  scope: [
                      :workspace_id,
                      :realm_id,
                      :public_id
                  ]
              },
              if: 'realm.present? && public.present? && private.present?'
    validates :workspace,
              presence: true

    private

    # Validates that at least one of {#private}, {#public}, or {#realm} is present.
    #
    # @return [void]
    def minimum_presence
      any_present = [:private, :public, :realm].any? { |attribute|
        send(attribute).present?
      }

      unless any_present
        errors.add(:base, :minimum_presence)
      end
    end

    # Validates that a Core's Private of type {Metasploit::Credential::SSHKey} has a {Metasploit::Credential::Public}
    def public_for_ssh_key
      if private.present? && private.type == Metasploit::Credential::SSHKey.name
        errors.add(:base, :public_for_ssh_key) unless public.present?
      end
    end


  end
end
