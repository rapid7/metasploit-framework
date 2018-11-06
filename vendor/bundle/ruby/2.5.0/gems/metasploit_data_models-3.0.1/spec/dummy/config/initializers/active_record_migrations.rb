# remove Dummy's db/migrate, which doesn't exists and replace it with gem's
ActiveRecord::Migrator.migrations_paths = [
    MetasploitDataModels.root.join('db', 'migrate').to_path
]