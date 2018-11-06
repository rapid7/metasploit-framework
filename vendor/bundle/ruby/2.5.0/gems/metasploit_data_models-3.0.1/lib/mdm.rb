# Namespace for models
module Mdm
  extend ActiveSupport::Autoload

  autoload :ApiKey
  autoload :Client
  autoload :Cred
  autoload :Event
  autoload :ExploitAttempt
  autoload :ExploitedHost
  autoload :Host
  autoload :HostDetail
  autoload :HostTag
  autoload :Listener
  autoload :Loot
  autoload :Macro
  autoload :ModRef
  autoload :Module
  autoload :NexposeConsole
  autoload :Note
  autoload :Profile
  autoload :Ref
  autoload :Route
  autoload :Service
  autoload :Session
  autoload :SessionEvent
  autoload :Tag
  autoload :Task
  autoload :TaskCred
  autoload :TaskHost
  autoload :TaskService
  autoload :TaskSession
  autoload :User
  autoload :Vuln
  autoload :VulnAttempt
  autoload :VulnDetail
  autoload :VulnRef
  autoload :WebForm
  autoload :WebPage
  autoload :WebSite
  autoload :WebVuln
  autoload :WmapRequest
  autoload :WmapTarget
  autoload :Workspace

  # Causes the model_name for all Mdm modules to not include the Mdm:: prefix in their name.
  #
  # This has been supported since ActiveSupport 3.2.1.  In ActiveSupport 3.1.0, it checked for _railtie.  Before that
  # there was no way to do relative naming without manually overriding model_name in each class.
  #
  # @return [true]
  def self.use_relative_model_naming?
    true
  end
end