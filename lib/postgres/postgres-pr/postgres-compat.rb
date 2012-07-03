# -*- coding: binary -*-
# This is a compatibility layer for using the pure Ruby postgres-pr instead of
# the C interface of postgres.

require 'postgres_msf'
require 'postgres/postgres-pr/connection'

# Namespace for Metasploit branch.
module Msf
module Db

class PGconn
  class << self
    alias connect new
  end

  def initialize(host, port, options, tty, database, user, auth)
    uri =
    if host.nil?
      nil
    elsif host[0] != ?/
      "tcp://#{ host }:#{ port }"
    else
      "unix:#{ host }/.s.PGSQL.#{ port }"
    end
    @host = host
    @db = database
    @user = user
    @conn = PostgresPR::Connection.new(database, user, auth, uri)
  end

  def close
    @conn.close
  end

  attr_reader :host, :db, :user

  def query(sql)
    PGresult.new(@conn.query(sql))
  end

  alias exec query

  def transaction_status
    @conn.transaction_status
  end

  def self.escape(str)
    str.gsub("'","''").gsub("\\", "\\\\\\\\")
  end

  def notice_processor
    @conn.notice_processor
  end

  def notice_processor=(np)
    @conn.notice_processor = np
  end

  def self.quote_ident(name)
    %("#{name}")
  end

end

class PGresult
  include Enumerable

  EMPTY_QUERY = 0
  COMMAND_OK = 1
  TUPLES_OK = 2
  COPY_OUT = 3
  COPY_IN = 4
  BAD_RESPONSE = 5
  NONFATAL_ERROR = 6
  FATAL_ERROR = 7

  def each(&block)
    @result.each(&block)
  end

  def [](index)
    @result[index]
  end
 
  def initialize(res)
    @res = res
    @fields = @res.fields.map {|f| f.name}
    @result = @res.rows
  end

  # TODO: status, getlength, cmdstatus

  attr_reader :result, :fields

  def num_tuples
    @result.size
  end

  def num_fields
    @fields.size
  end

  def fieldname(index)
    @fields[index]
  end

  def fieldnum(name)
    @fields.index(name)
  end

  def type(index)
    # TODO: correct?
    @res.fields[index].type_oid
  end

  def size(index)
    raise
    # TODO: correct?
    @res.fields[index].typlen
  end

  def getvalue(tup_num, field_num)
    @result[tup_num][field_num]
  end

  def status
    if num_tuples > 0
      TUPLES_OK
    else
      COMMAND_OK
    end
  end

  def cmdstatus
    @res.cmd_tag || ''
  end

  # free the result set
  def clear
    @res = @fields = @result = nil
  end

  # Returns the number of rows affected by the SQL command
  def cmdtuples
    case @res.cmd_tag
    when nil 
      return nil
    when /^INSERT\s+(\d+)\s+(\d+)$/, /^(DELETE|UPDATE|MOVE|FETCH)\s+(\d+)$/
      $2.to_i
    else
      nil
    end
  end

end

class PGError < ::Exception
end

end
end
