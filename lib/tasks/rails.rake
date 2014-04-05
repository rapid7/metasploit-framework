# Rake tasks added for compatibility with rake tasks that depend on a Rails
# environment, such as those in activerecord

# Would normally load config/environment.rb of the rails application.
#
# @see https://github.com/rails/rails/blob/e2908356672d4459ada0064f773efd820efda822/railties/lib/rails/application.rb#L190
task :environment do
	# ensures that Mdm models are available for migrations which use the models
	MetasploitDataModels.require_models

	# avoids the need for Rails.root in db:schema:dump
	schema_pathname = Metasploit::Framework.root.join('db', 'schema.rb')
	ENV['SCHEMA'] = schema_pathname.to_s
end

# This would normally default RAILS_ENV to development if ENV['RAILS_ENV'] is
# not set
#
# @see https://github.com/rails/rails/blob/1a275730b290c1f06d4e8df680d22ae1b41ab585/railties/lib/rails/tasks/misc.rake#L3
task :rails_env do
end
