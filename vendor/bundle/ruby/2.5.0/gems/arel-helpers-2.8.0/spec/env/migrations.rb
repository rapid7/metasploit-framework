# encoding: UTF-8

SuperClass = ActiveRecord::VERSION::MAJOR >= 5 && ActiveRecord::VERSION::MINOR >= 1 ? ActiveRecord::Migration[5.1] : ActiveRecord::Migration

class CreatePostsTable < SuperClass
  def change
    create_table :posts do |t|
      t.column :title, :string
    end
  end
end

class CreateCommentsTable < SuperClass
  def change
    create_table :comments do |t|
      t.references :post
    end
  end
end

class CreateAuthorsTable < SuperClass
  def change
    create_table :authors do |t|
      t.references :comment
      t.references :collab_posts
    end
  end
end

class CreateFavoritesTable < SuperClass
  def change
    create_table :favorites do |t|
      t.references :post
    end
  end
end

class CreateCollabPostsTable < SuperClass
  def change
    create_table :collab_posts do |t|
      t.references :authors
    end
  end
end

class CreateCardsTable < SuperClass
  def change
    create_table :cards
  end
end

class CreateCardLocationsTable < SuperClass
  def change
    create_table :card_locations do |t|
      t.references :location
      t.references :card, polymorphic: true
    end
  end
end

class CreateLocationsTable < SuperClass
  def change
    create_table :locations
  end
end

class CreateCommunityTicketsTable < SuperClass
  def change
    create_table :community_tickets
  end
end
