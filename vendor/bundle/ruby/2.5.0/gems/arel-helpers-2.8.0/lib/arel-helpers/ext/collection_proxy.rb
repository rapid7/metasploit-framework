# encoding: UTF-8

# ActiveRecord as of version 4.0 defines a CollectionProxy class that
# lazily fetches records from the database. If posts has many comments,
# then post.comments returns a CollectionProxy that can be iterated over.
# A query to fetch the pertinent records isn't fired until the iteration
# starts, so post.comments itself isn't enough to cause a trip to the
# database.
#
# ArelHelpers adds a [] method to ActiveRecord::Relation which means it
# also adds the same method to CollectionProxy, since CollectionProxy
# inherits from Relation. For some reason, CollectionProxy doesn't define
# its own [] method but instead lets ActiveRecord's complicated Delegation
# module handle calls to it via method_missing. In the post.comments case
# illustrated above, a call to [] is handled by this method_missing:
# https://github.com/rails/rails/blob/4-1-stable/activerecord/lib/active_record/relation/delegation.rb#L91
# Here, @klass refers to the Comment model, which means [] calls on an
# instance of CollectionProxy actually get re-routed. Instead of calling
# [] on a CollectionProxy like we were expecting, it calls [] on Comment,
# and therefore on the mixed-in ArelHelpers::ArelTable. The final result
# is that the caller gets back an Arel::Attribute instead of the instance
# of Comment they were expecting.
#
# This "simple" monkey patch defines [] on CollectionProxy so the convoluted
# method_missing logic in Delegation doesn't get triggered, and therefore
# doesn't end up returning an unexpected Arel::Attribute.
module ActiveRecord
  module Associations
    class CollectionProxy < Relation
      def [](index)
        to_a[index]
      end
    end
  end
end
