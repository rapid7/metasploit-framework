require 'active_record'
require 'minitest/autorun'
require 'bourne'
require 'database_cleaner'
unless ENV['CI'] || RUBY_PLATFORM =~ /java/
  require 'byebug'
end

require 'dotenv'
Dotenv.load

require 'postgres_ext'

ActiveRecord::Base.establish_connection(ENV['DATABASE_URL'])

class Person < ActiveRecord::Base
  has_many :hm_tags, class_name: 'Tag'
  has_and_belongs_to_many :habtm_tags, class_name: 'Tag'

  def self.wicked_people
    includes(:habtm_tags)
      .where(:tags => {:categories => ['wicked','awesome']})
  end
end

class Tag < ActiveRecord::Base
  belongs_to :person
end

class ParentTag < Tag
end

class ChildTag < Tag
  belongs_to :parent_tag, foreign_key: :parent_id
end

DatabaseCleaner.strategy = :deletion

class MiniTest::Spec
  class << self
    alias :context :describe
  end

  before do
    DatabaseCleaner.start
  end

  after do
    DatabaseCleaner.clean
  end
end
