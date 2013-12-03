# Seeds database after migration.
module Msf::DBManager::Seeding
  # Seeds database using seeds from `MetasploitDataModels`.
  def seed
    load Metasploit::Framework.root.join('db', 'seeds.rb').to_path
  end
end