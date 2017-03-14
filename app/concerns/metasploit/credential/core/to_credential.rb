# Adds associations to `Metasploit::Credential::Core` which are inverses of association on models under
# {BruteForce::Reuse}.
require 'metasploit/framework/credential'

module Metasploit::Credential::Core::ToCredential
  extend ActiveSupport::Concern
  
  included do
    
    def to_credential
      Metasploit::Framework::Credential.new(
        public:       public.try(:username) || '',
        private:      private.try(:data)    || '',
        private_type: private.try(:type).try(:demodulize).try(:underscore).try(:to_sym), 
        realm:        realm.try(:value), 
        realm_key:    realm.try(:key),
        parent:       self
      )
    end
    
  end
  
end
