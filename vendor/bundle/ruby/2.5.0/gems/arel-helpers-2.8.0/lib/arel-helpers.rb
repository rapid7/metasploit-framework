# encoding: UTF-8

require 'active_record'

begin
  ar_version = if ActiveRecord::VERSION.const_defined?(:STRING)
    ActiveRecord::VERSION::STRING
  else
    ActiveRecord.version.version
  end

  if ar_version >= '4.0.0'
    require 'arel-helpers/ext/collection_proxy'
  end
rescue
  puts 'ArelHelpers was unable to determine the version of ActiveRecord. You may encounter unexpected behavior.'
end

module ArelHelpers
  autoload :Aliases,         "arel-helpers/aliases"
  autoload :ArelTable,       "arel-helpers/arel_table"
  autoload :JoinAssociation, "arel-helpers/join_association"
  autoload :QueryBuilder,    "arel-helpers/query_builder"

  def self.join_association(*args, &block)
    ArelHelpers::JoinAssociation.join_association(*args, &block)
  end
end
