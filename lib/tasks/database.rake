load 'active_record/railties/databases.rake'

require 'metasploit/framework'
require 'metasploit/framework/database'

# A modification to remove dependency on Rails.env
#
# @see https://github.com/rails/rails/blob/ddce29bfa12462fde2342a0c2bd0eefd420c0eab/activerecord/lib/active_record/railties/databases.rake#L550
def configs_for_environment
  environments = [Metasploit::Framework.env]

  if Metasploit::Framework.env.development?
    environments << 'test'
  end

  environment_configurations = ActiveRecord::Base.configurations.values_at(*environments)
  present_environment_configurations = environment_configurations.compact
  valid_environment_configurations = present_environment_configurations.reject { |config|
    config['database'].blank?
  }

  valid_environment_configurations
end

# emulate initializer "active_record.initialize_database" from active_record/railtie
ActiveSupport.on_load(:active_record) do
  self.configurations = Metasploit::Framework::Database.configurations
  puts "Connecting to database specified by #{Metasploit::Framework::Database.configurations_pathname}"

  spec = configurations[Metasploit::Framework.env]
  establish_connection(spec)
end

#
# Remove tasks that aren't supported
#

Rake::TaskManager.class_eval do
  def remove_task(task_name)
    @tasks.delete(task_name.to_s)
  end
end

Rake.application.remove_task('db:fixtures:load')

# completely replace db:load_config and db:seed as they will attempt to use
# Rails.application, which does not exist
Rake::Task['db:load_config'].clear
Rake::Task['db:seed'].clear

db_namespace = namespace :db do
  task :load_config do
    ActiveRecord::Base.configurations = Metasploit::Framework::Database.configurations

    ActiveRecord::Migrator.migrations_paths = [
        # rails isn't in Gemfile, so can't use the more appropriate
        # Metasploit::Engine.instance.paths['db/migrate'].to_a since using
        # Metasploit::Engine requires rails.
        MetasploitDataModels.root.join('db', 'migrate').to_s
    ]
  end

  desc 'Load the seed data from db/seeds.rb'
  task :seed do
    db_namespace['abort_if_pending_migrations'].invoke
    seeds_pathname = Metasploit::Framework.root.join('db', 'seeds.rb')

    if seeds_pathname.exist?
      load(seeds_pathname)
    end
  end
end

