

## arel-helpers [![Build Status](https://secure.travis-ci.org/camertron/arel-helpers.png?branch=master)](http://travis-ci.org/camertron/arel-helpers)

Useful tools to help construct database queries with ActiveRecord and Arel.

## Installation

`gem install arel-helpers`

## Usage

```ruby
require 'arel-helpers'
```

### ArelTable Helper

Usually you'd reference database columns in Arel via the `#arel_table` method on your ActiveRecord models. For example:

```ruby
class Post < ActiveRecord::Base
  ...
end

Post.where(Post.arel_table[:id].eq(1))
```

Typing ".arel_table" over and over again can get pretty old and make constructing queries unnecessarily verbose. Try using the `ArelTable` helper to clean things up a bit:

```ruby
class Post < ActiveRecord::Base
  include ArelHelpers::ArelTable
  ...
end

Post.where(Post[:id].eq(1))
```

### JoinAssociation Helper

Using pure Arel is one of the only ways to do an outer join with ActiveRecord. For example, let's say we have these two models:

```ruby
class Author < ActiveRecord::Base
  has_many :posts

  # attribute id
  # attribute username
end

class Post < ActiveRecord::Base
  belongs_to :author
  has_many :comments

  # attribute id
  # attribute author_id
  # attribute subject
end

class Comment < ActiveRecord::Base
  belongs_to :post
  belongs_to :author

  # attribute id
  # attribute post_id
  # attribute author_id
end
```

A join between posts and comments might look like this:

```ruby
Post.joins(:comments)
```

ActiveRecord introspects the association between posts and comments and automatically chooses the right columns to use in the join conditions.

Things start to get messy however if you want to do an outer join instead of the default inner join. Your query might look like this:

```ruby
Post.joins(
  Post.arel_table.join(Comment.arel_table, Arel::Nodes::OuterJoin)
    .on(Post[:id].eq(Comment[:post_id]))
    .join_sources
)
```

Such verbose. Much code. Very bloat. Wow. We've lost all the awesome association introspection that ActiveRecord would otherwise have given us. Enter `ArelHelpers.join_association`:

```ruby
Post.joins(
  ArelHelpers.join_association(Post, :comments, Arel::Nodes::OuterJoin)
)
```

Easy peasy.

Note that pretty much anything you can pass to ActiveRecord's `#join` method you can also pass to `#join_association`'s second argument. For example, you can pass a hash to indicate a set of nested associations:

```ruby
Post.joins(
  ArelHelpers.join_association(Post, { comments: :author })
)
```

This might execute the following query:

```sql
SELECT "posts".*
FROM "posts"
INNER JOIN "comments" ON "comments"."post_id" = "posts"."id"
INNER JOIN "authors" ON "authors"."id" = "comments"."author_id"
```

`#join_association` also allows you to customize the join conditions via a block:

```ruby
Post.joins(
  ArelHelpers.join_association(Post, :comments, Arel::Nodes::OuterJoin) do |assoc_name, join_conditions|
    join_conditions.and(Post[:author_id].eq(4))
  end
)
```

But wait, there's more! Include the `ArelHelpers::JoinAssociation` concern into your models to have access to the `join_association` method directly from the model's class:

```ruby
include ArelHelpers::JoinAssociation

Post.joins(
  Post.join_association(:comments, Arel::Nodes::OuterJoin) do |assoc_name, join_conditions|
    join_conditions.and(Post[:author_id].eq(4))
  end
)
```

### Query Builders

ArelHelpers also contains a very simple class that's designed to provide a light framework for constructing queries using the builder pattern. For example, let's write a class that encapsulates generating queries for blog posts:

```ruby
class PostQueryBuilder < ArelHelpers::QueryBuilder
  def initialize(query = nil)
    # whatever you want your initial query to be
    super(query || post.unscoped)
  end

  def with_title_matching(title)
    reflect(
      query.where(post[:title].matches("%#{title}%"))
    )
  end

  def with_comments_by(usernames)
    reflect(
      query
        .joins(:comments => :author)
        .where(author[:username].in(usernames))
    )
  end

  def since_yesterday
    reflect(
      query.where(post[:created_at].gteq(Date.yesterday))
    )
  end

  private

  def author
    Author
  end

  def post
    Post
  end
end
```

The `#reflect` method creates a new instance of `PostQueryBuilder`, copies the query into it and returns the new query builder instance. This allows you to chain your method calls:

```ruby
PostQueryBuilder.new
  .with_comments_by(['camertron', 'catwithtail'])
  .with_title_matching("arel rocks")
  .since_yesterday
```

## Requirements

Requires ActiveRecord >= 3.1.0, < 6, tested against Ruby 2.2.4. Depends on SQLite for testing purposes.

## Running Tests

`bundle exec rspec`

## Authors

* Cameron C. Dutro: http://github.com/camertron
