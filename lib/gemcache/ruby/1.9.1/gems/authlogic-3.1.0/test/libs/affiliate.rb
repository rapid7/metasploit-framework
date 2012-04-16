class Affiliate < ActiveRecord::Base
  acts_as_authentic do |c|
    c.crypted_password_field = :pw_hash
  end
  
  belongs_to :company
end