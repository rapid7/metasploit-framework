# -*- coding: binary -*-
module Postgres::Conversion

  #
  # Encodes a string as bytea value.
  #
  # for encoding rules see:
  #   http://www.postgresql.org/docs/7.4/static/datatype-binary.html
  #

  def encode_bytea(str)
    str.gsub(/[\000-\037\047\134\177-\377]/) {|b| "\\#{ b[0].to_s(8).rjust(3, '0') }" }
  end

  #
  # Decodes a bytea encoded string.
  #
  # for decoding rules see:
  #   http://www.postgresql.org/docs/7.4/static/datatype-binary.html
  #
  def decode_bytea(str)
    str.gsub(/\\(\\|'|[0-3][0-7][0-7])/) {|s|
      if s.size == 2 then s[1,1] else s[1,3].oct.chr end
    }
  end

end
