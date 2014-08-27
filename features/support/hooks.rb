Before do
  set_env('RAILS_ENV', 'test')
  set_env('MSF_DATBASE_CONFIG', Rails.configuration.paths['config/database'].existent.first)
end

Before('@msfconsole') do
  step 'I run `msfconsole` interactively'
  step 'I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"'
  # we should not see the following
  # -- --=[ 0 exploits - 0 auxiliary - 0 post               ]
  # -- --=[ 0 payloads - 0 encoders - 0 nops                ]
end

Before('@targets') do
  step 'targets are loaded'
end

Before('@no-database-yml') do
  if File.exists?('config/database.yml') && File.exists?('config/database.yml.local')
    FileUtils.rm('config/database.yml.local') 
    FileUtils.mv('config/database.yml', 'config/database.yml.local')
  elsif File.exists?('config/database.yml')
    FileUtils.mv('config/database.yml', 'config/database.yml.local')
  end
end

After('@no-database-yml') do
  if File.exists?('config/database.yml') && File.exists?('config/database.yml.local')
    FileUtils.rm('config/database.yml')
    FileUtils.mv('config/database.yml.local', 'config/database.yml')
  elsif File.exists?('config/database.yml.local')
    FileUtils.mv('config/database.yml.local', 'config/database.yml')
  end
end