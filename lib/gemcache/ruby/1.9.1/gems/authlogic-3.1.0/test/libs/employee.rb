class Employee < ActiveRecord::Base
  acts_as_authentic do |c|
    c.crypto_provider Authlogic::CryptoProviders::AES256
  end
  
  belongs_to :company
end