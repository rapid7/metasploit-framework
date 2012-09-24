DatabaseCleaner[:active_record].strategy = :transaction if defined? ActiveRecord
DatabaseCleaner[:data_mapper].strategy = :transaction if defined? DataMapper
DatabaseCleaner[:mongoid].strategy = :truncation if defined? Mongoid
DatabaseCleaner[:mongo_mapper].strategy = :truncation if defined? MongoMapper

RSpec.configure do |config|
  config.before :suite do
    DatabaseCleaner.clean_with :truncation
  end
  config.before :each do
    DatabaseCleaner.start
  end
  config.after :each do
    DatabaseCleaner.clean
  end
end
