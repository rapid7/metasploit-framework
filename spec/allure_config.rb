require "allure-rspec"

AllureRspec.configure do |config|
  config.results_directory = "tmp/allure-raw-data"
  config.clean_results_directory = true
  config.logging_level = Logger::INFO
  config.logger = Logger.new($stdout, Logger::DEBUG)
  config.environment = RbConfig::CONFIG['host_os']

  # Add additional metadata to allure
  environment_properties = {
    host_os: RbConfig::CONFIG['host_os'],
    ruby_version: RUBY_VERSION,
    host_runner_image: ENV['HOST_RUNNER_IMAGE'],
  }.compact
  session_name = ENV['SESSION']
  session_runtime_version = ENV['SESSION_RUNTIME_VERSION']
  if session_name.present?
    environment_properties[:session_name] = session_name
    if session_runtime_version.present?
      environment_properties[:session_runtime_version] = "#{session_name}#{session_runtime_version}"
    end
  end
  environment_properties[:runtime_version] = ENV['RUNTIME_VERSION']

  config.environment_properties = environment_properties.compact
end
