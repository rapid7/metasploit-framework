if defined?(Rails)
  # Track all of the applicable locales to load
  locale_paths = []
  StateMachine::Integrations.all.each do |integration|
    locale_paths << integration.locale_path if integration.available? && integration.locale_path
  end
  
  if defined?(Rails::Engine)
    # Rails 3.x
    class StateMachine::RailsEngine < Rails::Engine
      rake_tasks do
        load 'tasks/state_machine.rb'
      end
    end
    
    if Rails::VERSION::MAJOR == 3 && Rails::VERSION::MINOR == 0
      StateMachine::RailsEngine.paths.config.locales = locale_paths
    else
      StateMachine::RailsEngine.paths['config/locales'] = locale_paths
    end
  elsif defined?(I18n)
    # Rails 2.x
    I18n.load_path.unshift(*locale_paths)
  end
end
