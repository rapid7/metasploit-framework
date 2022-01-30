class ApplicationRecord < ActiveRecord::Base
  self.abstract_class = true
  include ArelHelpers::ArelTable
  include ArelHelpers::JoinAssociation
end
