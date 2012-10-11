class User
  include ::DataMapper::Resource

  property :id, Serial
  property :name, String, :required => true
  property :age, Integer

  has n, :projects, :through => Resource
end

class User::Address
  include ::DataMapper::Resource

  property :id, Serial
end

class Project
  include ::DataMapper::Resource

  property :id, Serial
  property :name, String, :required => true

  has n, :users, :through => Resource
end

DataMapper.finalize
DataMapper.auto_migrate!
