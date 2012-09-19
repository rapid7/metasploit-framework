require "active_record"

AUTHLOGIC_PATH = File.dirname(__FILE__) + "/authlogic/"

[
 "i18n",
 "random",
 "regex",
 
 "controller_adapters/abstract_adapter",
 
 "crypto_providers/md5",
 "crypto_providers/sha1",
 "crypto_providers/sha256",
 "crypto_providers/sha512",
 "crypto_providers/bcrypt",
 "crypto_providers/aes256",
 
 "authenticates_many/base",
 "authenticates_many/association",
 
 "acts_as_authentic/email",
 "acts_as_authentic/logged_in_status",
 "acts_as_authentic/login",
 "acts_as_authentic/magic_columns",
 "acts_as_authentic/password",
 "acts_as_authentic/perishable_token",
 "acts_as_authentic/persistence_token",
 "acts_as_authentic/restful_authentication",
 "acts_as_authentic/session_maintenance",
 "acts_as_authentic/single_access_token",
 "acts_as_authentic/validations_scope",
 "acts_as_authentic/base",
 
 "session/activation",
 "session/active_record_trickery",
 "session/brute_force_protection",
 "session/callbacks",
 "session/cookies",
 "session/existence",
 "session/foundation",
 "session/http_auth",
 "session/id",
 "session/klass",
 "session/magic_columns",
 "session/magic_states",
 "session/params",
 "session/password",
 "session/perishable_token",
 "session/persistence",
 "session/priority_record",
 "session/scopes",
 "session/session",
 "session/timeout",
 "session/unauthorized_record",
 "session/validation",
 "session/base"
].each do |library|
   require AUTHLOGIC_PATH + library
 end

require AUTHLOGIC_PATH + "controller_adapters/rails_adapter"   if defined?( Rails   )
require AUTHLOGIC_PATH + "controller_adapters/merb_adapter"    if defined?( Merb    )
require AUTHLOGIC_PATH + "controller_adapters/sinatra_adapter" if defined?( Sinatra )
