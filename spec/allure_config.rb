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
  meterpreter_name = ENV['METERPRETER']
  meterpreter_runtime_version = ENV['METERPRETER_RUNTIME_VERSION']
  if meterpreter_name.present?
    environment_properties[:meterpreter_name] = meterpreter_name
    if meterpreter_runtime_version.present?
      environment_properties[:meterpreter_runtime_version] = "#{meterpreter_name}#{meterpreter_runtime_version}"
    end
  end

  config.environment_properties = environment_properties.compact
end
