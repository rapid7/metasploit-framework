# encoding: UTF-8

class Post < ActiveRecord::Base
  include ArelHelpers::ArelTable
  include ArelHelpers::Aliases
  has_many :comments
  has_many :favorites
end

class Comment < ActiveRecord::Base
  include ArelHelpers::ArelTable
  include ArelHelpers::Aliases
  belongs_to :post
  belongs_to :author
end

class Author < ActiveRecord::Base
  include ArelHelpers::ArelTable
  include ArelHelpers::Aliases
  has_one :comment
  has_and_belongs_to_many :collab_posts
end

class Favorite < ActiveRecord::Base
  include ArelHelpers::ArelTable
  include ArelHelpers::Aliases
  belongs_to :post
end

class CollabPost < ActiveRecord::Base
  include ArelHelpers::ArelTable
  include ArelHelpers::Aliases
  has_and_belongs_to_many :authors
end

class Card < ActiveRecord::Base
  has_many :card_locations
end

class CardLocation < ActiveRecord::Base
  belongs_to :location
  belongs_to :card, polymorphic: true
end

class Location < ActiveRecord::Base
  has_many :card_locations
  has_many :community_tickets, {
    through: :card_locations, source: :card, source_type: 'CommunityTicket'
  }
end

class CommunityTicket < ActiveRecord::Base
  has_many :card_locations, as: :card, source_type: 'CommunityTicket'
  has_many :locations, through: :card_locations
end
