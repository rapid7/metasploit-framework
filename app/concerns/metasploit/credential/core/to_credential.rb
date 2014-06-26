# Adds associations to `Metasploit::Credential::Core` which are inverses of association on models under
# {BruteForce::Reuse}.
module Metasploit::Credential::Core::ToCredential
  extend ActiveSupport::Concern
  
  included do
    
    def to_credential
      Metasploit::Framework::Credential.new(public: public.try(:username), private: private.try(:data), realm: realm.try(:value) )
    end
    
  end
  
end
