Before do
  set_env('MSF_DATBASE_CONFIG', Rails.configuration.paths['config/database'].existent.first)
  set_env('RAILS_ENV', 'test')
  @aruba_timeout_seconds = 4.minutes
end