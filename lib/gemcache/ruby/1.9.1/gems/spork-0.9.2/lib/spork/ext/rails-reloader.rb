Spork.each_run do
  ::ActiveSupport.const_defined?(:Dependencies) ?
    ::ActiveSupport::Dependencies.mechanism = :load :
    ::Dependencies.mechanism = :load

  require 'action_controller/dispatcher'
  dispatcher = ::ActionController::Dispatcher.new($stdout)

  if ::ActionController::Dispatcher.respond_to?(:reload_application)
    ::ActionController::Dispatcher.reload_application
  else
    dispatcher.reload_application
  end
end if Spork.using_spork?