module Anemone
  module Storage

    def self.Hash(*args)
      hash = Hash.new(*args)
      # add close method for compatibility with Storage::Base
      class << hash; def close; end; end
      hash
    end

    def self.PStore(*args)
      require 'anemone/storage/pstore'
      self::PStore.new(*args)
    end

    def self.TokyoCabinet(file = 'anemone.tch')
      require 'anemone/storage/tokyo_cabinet'
      self::TokyoCabinet.new(file)
    end

    def self.MongoDB(mongo_db = nil, collection_name = 'pages')
      require 'anemone/storage/mongodb'
      mongo_db ||= Mongo::Connection.new.db('anemone')
      raise "First argument must be an instance of Mongo::DB" unless mongo_db.is_a?(Mongo::DB)
      self::MongoDB.new(mongo_db, collection_name)
    end

    def self.Redis(opts = {})
      require 'anemone/storage/redis'
      self::Redis.new(opts)
    end

  end
end
