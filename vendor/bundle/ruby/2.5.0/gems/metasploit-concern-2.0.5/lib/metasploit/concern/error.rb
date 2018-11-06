# Namespace for errors raised by {Metasploit::Concern}.
module Metasploit::Concern::Error
  extend ActiveSupport::Autoload

  autoload :Base
  autoload :EagerLoad
  autoload :SkipAutoload
end
