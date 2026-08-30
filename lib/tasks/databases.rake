namespace :db do
  # Add onto the task so that after adding Rails.application.paths['db/migrate']
  task :load_config do
    # It's important to call to_a or the paths will just be relative and not realpaths
    gem_migrations = Metasploit::Credential::Engine.instance.paths['db/migrate'].to_a
    ActiveRecord::Migrator.migrations_paths += gem_migrations
    ActiveRecord::Tasks::DatabaseTasks.migrations_paths += gem_migrations
  end
end