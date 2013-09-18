ActiveRecord::Base.connection_pool.with_connection do
  load MetasploitDataModels.root.join('db', 'seeds.rb').to_path
end