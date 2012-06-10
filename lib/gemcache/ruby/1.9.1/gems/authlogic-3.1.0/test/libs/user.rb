class User < ActiveRecord::Base
  acts_as_authentic
  belongs_to :company
  has_and_belongs_to_many :projects
end