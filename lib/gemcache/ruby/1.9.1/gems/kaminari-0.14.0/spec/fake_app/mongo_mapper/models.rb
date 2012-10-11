class User
  include ::MongoMapper::Document
  key :name, String
  key :age, Integer
end

class User::Address
  include ::MongoMapper::Document
end
