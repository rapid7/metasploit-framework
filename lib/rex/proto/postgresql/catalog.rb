# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    module PostgreSQL
      #
      # PostgreSQL System Catalog Parser (pg_class, pg_attribute)
      #
      module Catalog
        # System catalog OIDs (fixed in all PostgreSQL versions)
        # Source: src/include/catalog/pg_*.h in PostgreSQL source
        PG_TYPE = 1247          # pg_type - data types
        PG_ATTRIBUTE = 1249     # pg_attribute - table columns
        PG_CLASS = 1259         # pg_class - tables/indexes
        PG_AUTHID = 1260        # pg_authid - users/roles (global)
        PG_AUTH_MEMBERS = 1261  # pg_auth_members - role membership (global)
        PG_DATABASE = 1262      # pg_database - databases (global)

        # Stable system catalog schemas (PostgreSQL 12+)
        # Only includes columns that are stable across all versions
        PG_CLASS_SCHEMA = [
          { name: 'oid', typid: 26, len: 4 },
          { name: 'relname', typid: 19, len: 64 },
          { name: 'relnamespace', typid: 26, len: 4 },
          { name: 'reltype', typid: 26, len: 4 },
          { name: 'reloftype', typid: 26, len: 4 },
          { name: 'relowner', typid: 26, len: 4 },
          { name: 'relam', typid: 26, len: 4 },
          { name: 'relfilenode', typid: 26, len: 4 },
          { name: 'reltablespace', typid: 26, len: 4 },
          { name: 'relpages', typid: 23, len: 4 },
          { name: 'reltuples', typid: 700, len: 4 },
          { name: 'relallvisible', typid: 23, len: 4 },
          { name: 'reltoastrelid', typid: 26, len: 4 },
          { name: 'relhasindex', typid: 16, len: 1 },
          { name: 'relisshared', typid: 16, len: 1 },
          { name: 'relpersistence', typid: 18, len: 1 },
          { name: 'relkind', typid: 18, len: 1 }
        ].freeze

        # pg_attribute schema varies between PostgreSQL versions:
        # - PG12-15: attrelid, attname, atttypid, attstattarget, attlen, attnum
        # - PG16+:   attrelid, attname, atttypid, attlen, attnum (attstattarget moved)
        PG_ATTRIBUTE_SCHEMA_V15 = [
          { name: 'attrelid', typid: 26, len: 4 },
          { name: 'attname', typid: 19, len: 64 },
          { name: 'atttypid', typid: 26, len: 4 },
          { name: 'attstattarget', typid: 23, len: 4 },
          { name: 'attlen', typid: 21, len: 2 },
          { name: 'attnum', typid: 21, len: 2 }
        ].freeze

        PG_ATTRIBUTE_SCHEMA_V16 = [
          { name: 'attrelid', typid: 26, len: 4 },
          { name: 'attname', typid: 19, len: 64 },
          { name: 'atttypid', typid: 26, len: 4 },
          { name: 'attlen', typid: 21, len: 2 },
          { name: 'attnum', typid: 21, len: 2 }
        ].freeze

        class << self
          def parse_pg_class(tuples)
            parse_tuples(tuples, PG_CLASS_SCHEMA) do |row|
              next unless row['relfilenode']&.positive?

              [row['relfilenode'], class_entry(row)]
            end
          end

          def parse_pg_attribute(tuples, pg_version = nil)
            schema = select_attribute_schema(tuples, pg_version)
            result = Hash.new { |h, k| h[k] = [] }
            parse_tuples(tuples, schema) do |row|
              next unless row['attrelid']&.positive? && row['attnum']&.positive?

              result[row['attrelid']] << attr_entry(row)
              nil
            end
            result.transform_values { |v| v.sort_by { |c| c[:num] } }
          end

          def select_attribute_schema(tuples, pg_version)
            return PG_ATTRIBUTE_SCHEMA_V16 if pg_version.to_i >= 16
            return PG_ATTRIBUTE_SCHEMA_V15 if pg_version.to_i.between?(12, 15)

            # Auto-detect: first tuples should have sequential positive attnum (1,2,3...)
            # V16 schema on V15 data gives attnum=-1 (wrong), V15 schema gives 1,2,3...
            sample = tuples.first(5)
            v16_results = sample.map do |t|
              row = HeapFile.decode_tuple(t[:tuple], PG_ATTRIBUTE_SCHEMA_V16) rescue nil
              row&.dig('attnum')
            end

            # If V16 schema gives sequential 1,2,3,4,5 it's correct, otherwise use V15
            v16_results == [1, 2, 3, 4, 5] ? PG_ATTRIBUTE_SCHEMA_V16 : PG_ATTRIBUTE_SCHEMA_V15
          end

          def build_schema(class_tuples, attr_tuples)
            tables = parse_pg_class(class_tuples)
            columns = parse_pg_attribute(attr_tuples)

            tables.transform_values do |info|
              { name: info[:name], kind: info[:kind], columns: columns[info[:oid]] || [] }
            end
          end

          private

          def parse_tuples(tuples, schema)
            tuples.each_with_object({}) do |tuple, acc|
              row = HeapFile.decode_tuple(tuple[:tuple], schema)
              next unless row

              result = yield(row)
              acc[result[0]] = result[1] if result
            rescue StandardError
              next
            end
          end

          def class_entry(row)
            { oid: row['oid'], name: row['relname'], namespace: row['relnamespace'],
              filenode: row['relfilenode'], kind: row['relkind'] }
          end

          def attr_entry(row)
            { name: row['attname'], typid: row['atttypid'], num: row['attnum'], len: row['attlen'] }
          end
        end
      end
    end
  end
end
