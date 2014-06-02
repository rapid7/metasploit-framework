namespace :db do
  # Add onto the task so that after adding Rails.application.paths['db/migrate']
  task :load_config do
    # It's important to call to_a or the paths will just be relative and not realpaths
    ActiveRecord::Migrator.migrations_paths += Metasploit::Credential::Engine.instance.paths['db/migrate'].to_a
  end
end