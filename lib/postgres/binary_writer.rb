# -*- coding: binary -*-
require 'postgres_msf'
require 'postgres/byteorder'

# Namespace for Metasploit branch.
module Msf
module Db

module BinaryWriterMixin

  # == 8 bit

  # no byteorder for 8 bit! 

  def write_word8(val)
    pw(val, 'C')
  end

  def write_int8(val)
    pw(val, 'c')
  end

  alias write_byte write_word8

  # == 16 bit

  # === Unsigned

  def write_word16_native(val)
    pw(val, 'S')
  end

  def write_word16_little(val)
    str = [val].pack('S')
    str.reverse! if ByteOrder.network? # swap bytes as native=network (and we want little)
    write(str)
  end

  def write_word16_network(val)
    str = [val].pack('S')
    str.reverse! if ByteOrder.little? # swap bytes as native=little (and we want network)
    write(str)
  end

  # === Signed

  def write_int16_native(val)
    pw(val, 's')
  end

  def write_int16_little(val)
    pw(val, 'v')
  end

  def write_int16_network(val)
    pw(val, 'n')
  end

  # == 32 bit

  # === Unsigned

  def write_word32_native(val)
    pw(val, 'L')
  end

  def write_word32_little(val)
    str = [val].pack('L')
    str.reverse! if ByteOrder.network? # swap bytes as native=network (and we want little)
    write(str)
  end

  def write_word32_network(val)
    str = [val].pack('L')
    str.reverse! if ByteOrder.little? # swap bytes as native=little (and we want network)
    write(str)
  end

  # === Signed

  def write_int32_native(val)
    pw(val, 'l')
  end

  def write_int32_little(val)
    pw(val, 'V')
  end

  def write_int32_network(val)
    pw(val, 'N')
  end

  # add some short-cut functions 
  %w(word16 int16 word32 int32).each do |typ|
    alias_method "write_#{typ}_big", "write_#{typ}_network"
  end

  # == Other methods

  private

  # shortcut for pack and write
  def pw(val, template)
    write([val].pack(template))
  end
end

end
end
