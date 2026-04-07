# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    #
    # PostgreSQL Protocol and Storage Utilities
    #
    # Provides parsers for PostgreSQL binary formats enabling direct
    # reading of database files without SQL access:
    #
    # - Page: Parse heap page headers and extract tuples
    # - HeapTuple: Parse tuple headers and visibility info
    # - Types: Decode PostgreSQL data types (int, text, jsonb, etc.)
    # - Catalog: Parse system catalogs (pg_class, pg_attribute)
    # - HeapFile: High-level file reading interface
    # - Jsonb: Parse JSONB binary format
    #
    # @example Read tuples from a table file
    #   data = File.binread('/var/lib/postgresql/data/base/12345/16384')
    #   tuples = Rex::Proto::PostgreSQL::HeapFile.read_tuples(data)
    #
    # @example Extract JSONB secrets
    #   secrets = Rex::Proto::PostgreSQL::Jsonb.scan_objects(data, filter_keys: ['secret'])
    #
    # @see https://www.postgresql.org/docs/current/storage.html
    # @author Valentin Lobstein (Chocapikk)
    #
    module PostgreSQL
    end
  end
end

require_relative 'postgresql/page'
require_relative 'postgresql/heap_tuple'
require_relative 'postgresql/types'
require_relative 'postgresql/catalog'
require_relative 'postgresql/heap_file'
require_relative 'postgresql/jsonb'
