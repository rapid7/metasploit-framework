module Metasploit::Framework::Spec::DatabaseCleaner
  def self.configure!
    unless @configured
      # connection must be established by activerecord's before(:suite) before database cleaner's before(:suite)
      Metasploit::Framework::Spec::ActiveRecord.configure!

      RSpec.configure do |config|
        config.before(:suite) do
          # full clean, all tables
          ::DatabaseCleaner.clean_with(:truncation)

          # refill seeds
          load Metasploit::Framework.root.join('db', 'seeds.rb').to_path

          # setup to clean all, but seed tables
          seeded_classes = [
              Mdm::Architecture,
              # authority is partially seeded and partially created on the fly, but it's simpler to treat it as completely
              # seeded because realistically any on-the-fly authorities should be added to the seeds
              Mdm::Authority,
              Mdm::Platform,
              Mdm::Module::Rank
          ]
          table_names = seeded_classes.map(&:table_name)
          ::DatabaseCleaner.strategy = [
              :deletion,
              {
                  except: table_names
              }
          ]
        end
      end

      @configured = true
    end
  end
end