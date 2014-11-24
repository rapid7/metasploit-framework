Before do
  set_env('MSF_DATBASE_CONFIG', Rails.configuration.paths['config/database'].existent.first)
  set_env('RAILS_ENV', 'test')
  @aruba_timeout_seconds = 8.minutes
end

Before do |scenario|
  command_name = case scenario
                 when Cucumber::Ast::Scenario, Cucumber::Ast::ScenarioOutline
                   "#{scenario.feature.title} #{scenario.name}"
                 when Cucumber::Ast::OutlineTable::ExampleRow
                   scenario_outline = scenario.scenario_outline

                   "#{scenario_outline.feature.title} #{scenario_outline.name} #{scenario.name}"
                 else
                   raise TypeError, "Don't know how to extract command name from #{scenario.class}"
                 end

  # Used in simplecov_setup so that each scenario has a different name and their coverage results are merged instead
  # of overwriting each other as 'Cucumber Features'
  set_env('SIMPLECOV_COMMAND_NAME', command_name)

  simplecov_setup_pathname = Pathname.new(__FILE__).expand_path.parent.join('simplecov_setup')
  # set environment variable so child processes will merge their coverage data with parent process's coverage data.
  set_env('RUBYOPT', "-r#{simplecov_setup_pathname} #{ENV['RUBYOPT']}")
end
