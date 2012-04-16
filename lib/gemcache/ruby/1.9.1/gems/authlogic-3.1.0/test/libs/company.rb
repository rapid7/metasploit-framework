class Company < ActiveRecord::Base
  authenticates_many :employee_sessions
  authenticates_many :user_sessions
  has_many :employees, :dependent => :destroy
  has_many :users, :dependent => :destroy
end