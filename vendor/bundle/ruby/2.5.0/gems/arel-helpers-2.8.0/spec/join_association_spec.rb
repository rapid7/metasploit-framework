# encoding: UTF-8

require 'spec_helper'

describe ArelHelpers do
  describe "#join_association" do
    it "should work for a directly associated model" do
      Post.joins(ArelHelpers.join_association(Post, :comments)).to_sql.should ==
        'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id"'
    end

    it "should work with an outer join" do
      Post.joins(ArelHelpers.join_association(Post, :comments, Arel::Nodes::OuterJoin)).to_sql.should ==
        'SELECT "posts".* FROM "posts" LEFT OUTER JOIN "comments" ON "comments"."post_id" = "posts"."id"'
    end

    it "should allow adding additional join conditions" do
      Post.joins(ArelHelpers.join_association(Post, :comments) do |assoc_name, join_conditions|
        join_conditions.and(Comment[:id].eq(10))
      end).to_sql.should ==
        'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id" AND "comments"."id" = 10'
    end

    it "should work for two models, one directly associated and the other indirectly" do
      Post
        .joins(ArelHelpers.join_association(Post, :comments))
        .joins(ArelHelpers.join_association(Comment, :author))
        .to_sql.should ==
          'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id" INNER JOIN "authors" ON "authors"."id" = "comments"."author_id"'
    end

    it "should work for a nested hash of association names" do
      Post
        .joins(ArelHelpers.join_association(Post, { comments: :author }))
        .to_sql.should ==
          'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id" INNER JOIN "authors" ON "authors"."id" = "comments"."author_id"'
    end

    it "should work with outer joins when given a nested hash of association names" do
      Post
        .joins(ArelHelpers.join_association(Post, { comments: :author }, Arel::Nodes::OuterJoin))
        .to_sql.should ==
          'SELECT "posts".* FROM "posts" LEFT OUTER JOIN "comments" ON "comments"."post_id" = "posts"."id" LEFT OUTER JOIN "authors" ON "authors"."id" = "comments"."author_id"'
    end

    it "should be able to handle multiple associations" do
      Post.joins(ArelHelpers.join_association(Post, [:comments, :favorites])).to_sql.should ==
        'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id" INNER JOIN "favorites" ON "favorites"."post_id" = "posts"."id"'
    end

    it "should yield once for each association" do
      Post.joins(ArelHelpers.join_association(Post, [:comments, :favorites]) do |assoc_name, join_conditions|
        case assoc_name
          when :favorites
            join_conditions.or(Favorite[:amount].eq("lots"))
          when :comments
            join_conditions.and(Comment[:text].eq("Awesome post!"))
        end
      end).to_sql.should ==
        'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id" AND "comments"."text" = \'Awesome post!\' INNER JOIN "favorites" (ON "favorites"."post_id" = "posts"."id" OR "favorites"."amount" = \'lots\')'
    end

    it 'should be able to handle has_and_belongs_to_many associations' do
      CollabPost.joins(ArelHelpers.join_association(CollabPost, :authors)).to_sql.should ==
        'SELECT "collab_posts".* FROM "collab_posts" INNER JOIN "authors_collab_posts" ON "authors_collab_posts"."collab_post_id" = "collab_posts"."id" INNER JOIN "authors" ON "authors"."id" = "authors_collab_posts"."author_id"'
    end

    it "allows adding a custom alias to the joined table" do
      Comment.aliased_as(:foo) do |foo|
        Post.joins(ArelHelpers.join_association(Post, :comments, Arel::Nodes::InnerJoin, aliases: [foo])).to_sql.should ==
          'SELECT "posts".* FROM "posts" INNER JOIN "comments" "foo" ON "foo"."post_id" = "posts"."id"'
      end
    end

    it "allows aliasing multiple associations" do
      Comment.aliased_as(:foo) do |foo|
        Favorite.aliased_as(:bar) do |bar|
          Post.joins(ArelHelpers.join_association(Post, [:comments, :favorites], Arel::Nodes::InnerJoin, aliases: [foo, bar])).to_sql.should ==
            'SELECT "posts".* FROM "posts" INNER JOIN "comments" "foo" ON "foo"."post_id" = "posts"."id" INNER JOIN "favorites" "bar" ON "bar"."post_id" = "posts"."id"'
        end
      end
    end

    it 'handles polymorphic through associations' do
      relation = Location.joins(
        ArelHelpers.join_association(Location, :community_tickets)
      )

      relation.to_sql.should == 'SELECT "locations".* FROM "locations" ' +
        'INNER JOIN "card_locations" ON "card_locations"."location_id" = "locations"."id" AND "card_locations"."card_type" = \'CommunityTicket\' ' +
        'INNER JOIN "community_tickets" ON "community_tickets"."id" = "card_locations"."card_id"'
    end
  end
end

describe ArelHelpers::JoinAssociation do
  class AssocPost < Post
    include ArelHelpers::JoinAssociation
  end

  it "should provide the join_association method and use the parent class as the model to join on" do
    AssocPost.joins(AssocPost.join_association(:comments)).to_sql.should ==
      'SELECT "posts".* FROM "posts" INNER JOIN "comments" ON "comments"."post_id" = "posts"."id"'
  end
end
