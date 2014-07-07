# Adds associations to `Metasploit::Credential::Core` which are inverses of association on models under
# {BruteForce::Reuse}.
require 'metasploit/framework/credential'

module Metasploit::Credential::Core::ToCredential
  extend ActiveSupport::Concern
  
  included do
    
    def to_credential
      if private.present?
        private_type = private.type.demodulize.underscore.to_sym
      else
        private_type = nil
      end
      Metasploit::Framework::Credential.new(public: public.try(:username), private: private.try(:data), private_type: private_type, realm: realm.try(:value), realm_key: realm.try(:key) )
    end
    
  end
  
end
