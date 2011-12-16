= BitStruct

Class for packed binary data stored in ruby Strings. BitStruct accessors, generated from user declared fields, use pack/unpack to treat substrings as fields with a specified portable format.

Field types include:

* signed and unsigned integer (1..16 bits, or 24, 32, 40, 48... bits)

* numeric fields (signed, unsigned, float) can be designated as any of the following endians: little, big, native, network (default)

* fixed point, with arbitrary scale factor

* fixed length character array

* null-terminated character array for printable text

* octets (hex and decimal representation options; useful for IP and MAC addrs)

* float

* nested BitStruct

* vectors of embedded BitStructs

* free-form "rest" field (e.g., for the variable-size payload of a packet)

Field options (specifiable as :foo => val or "foo" => val) include:

* *display_name*: used in BitStruct#inspect_detailed and BitStruct#describe outputs.

* *default*: default field value

* *format*: alternate format string for inspect

* *endian*: for byte ordering of numeric fields (unsigned, signed, float): little, big, native, network (default)

* *fixed*: float stored as fixed-point integer, with specified scale factor


== Installation

For .gem:

  gem install bit-struct

For .tgz, unpack and then:

  ruby install.rb config
  ruby install.rb setup
  ruby install.rb install

== Uses

BitStruct is useful for defining packets used in network protocols. This is especially useful for raw IP--see examples/ping-recv.rb. All multibyte numeric fields are stored by default in network order.

BitStruct is most efficient when your data is primarily treated as a binary string, and only secondarily treated as a data structure. (For instance, you are routing packets from one socket to another, possibly looking at one or two fields as it passes through or munging some headers.) If accessor operations are a bottleneck, a better approach is to define a class that wraps an array and uses pack/unpack when the object needs to behave like a binary string.

== Features

* Extensible with user-defined field classes.

* Fields are fully introspectable and can be defined programmatically.

* BitStruct.describe prints out documentation of all the fields of a BitStruct subclass, based on declarations. This is useful for communicating with developers who are not using ruby, but need to talk the same protocols. See Example, below.

* Fields are inherited by subclasses. (The free-form "rest" field does not inherit, because it usually represents a payload whose structure is defined in subclasses using the fixed-size fields.)

* BitStruct#inspect and BitStruct#inspect_detailed can be used for prettified display of contents. (More generally, BitStruct#inspect takes some options that control formatting and detail level.) See Example, below.

* BitStruct inherits from String, so all the usual methods are available, and string-sharing (copy-on-write) is in effect.

* Easy access to a "prototype" instance of each BitStruct subclass, from which all instances of that subclass are initialized as a copy (in the absence of other initialization parameters, such as a hash, a string, or a block). See BitStruct.initial_value, and BitStruct#initialize. See Example, below.

* Easy conversion to and from hashes, using BitStruct#to_h and BitStruct.new.

* BitStructs can persist using Marshal (a BitStruct is after all just a string) or using YAML (with human readable representation of the fields).

* Includes tests, examples, and rdoc API documentation.

== Limitations

* Fields that are not aligned on byte boundaries may cross no more than two bytes boundaries. (See examples/byte-bdy.rb.)

* No variable length fields (except the #rest field).
 
== Future plans

* Currently, the library is written in pure ruby. The implementation uses Array#pack and String#unpack calls, as well as shifting and masking in pure ruby. Future versions will optionally generate a customized C extension for better efficiency.

* A debug mode in which a class identifier is prepended to every BitStruct, so that protocol errors can be detected. (This feature has been implemented in an app that uses BitStruct, but needs to be refactored into the BitStruct library itself.)

* Remove field size and alignment limitations.

== Example

An IP packet can be defined and used like this:

  require 'bit-struct'

  class IP < BitStruct
    unsigned    :ip_v,     4,     "Version"
    unsigned    :ip_hl,    4,     "Header length"
    unsigned    :ip_tos,   8,     "TOS"
    unsigned    :ip_len,  16,     "Length"
    unsigned    :ip_id,   16,     "ID"
    unsigned    :ip_off,  16,     "Frag offset"
    unsigned    :ip_ttl,   8,     "TTL"
    unsigned    :ip_p,     8,     "Protocol"
    unsigned    :ip_sum,  16,     "Checksum"
    octets      :ip_src,  32,     "Source addr"
    octets      :ip_dst,  32,     "Dest addr"
    rest        :body,            "Body of message"

    note "     rest is application defined message body"

    initial_value.ip_v    = 4
    initial_value.ip_hl   = 5
  end

  ip = IP.new
  ip.ip_tos = 0
  ip.ip_len = 0
  ip.ip_id  = 0
  ip.ip_off = 0
  ip.ip_ttl = 255
  ip.ip_p   = 255
  ip.ip_sum = 0
  ip.ip_src = "192.168.1.4"
  ip.ip_dst = "192.168.1.255"
  ip.body   = "This is the payload text."
  ip.ip_len = ip.length

  puts ip.inspect
  puts "-"*50
  puts ip.inspect_detailed
  puts "-"*50
  puts IP.describe

(Note that you can also construct an IP packet by passing a string to new, or by passing a hash of <tt>field,value</tt> pairs, or by providing a block that is yielded the new BitStruct.)

The output of this fragment is:

  #<IP ip_v=4, ip_hl=5, ip_tos=0, ip_len=45, ip_id=0, ip_off=0, ip_ttl=255, ip_p=255, ip_sum=0, ip_src="192.168.1.4", ip_dst="192.168.1.255", body="This is the payload text.">
  --------------------------------------------------
  IP:
                         Version = 4
                   Header length = 5
                             TOS = 0
                          Length = 45
                              ID = 0
                     Frag offset = 0
                             TTL = 255
                        Protocol = 255
                        Checksum = 0
                     Source addr = "192.168.1.4"
                       Dest addr = "192.168.1.255"
                 Body of message = "This is the payload text."
  --------------------------------------------------

  Description of IP Packet:
      byte: type         name          [size] description
  ----------------------------------------------------------------------
        @0: unsigned     ip_v          [  4b] Version
        @0: unsigned     ip_hl         [  4b] Header length
        @1: unsigned     ip_tos        [  8b] TOS
        @2: unsigned     ip_len        [ 16b] Length
        @4: unsigned     ip_id         [ 16b] ID
        @6: unsigned     ip_off        [ 16b] Frag offset
        @8: unsigned     ip_ttl        [  8b] TTL
        @9: unsigned     ip_p          [  8b] Protocol
       @10: unsigned     ip_sum        [ 16b] Checksum
       @12: octets       ip_src        [ 32b] Source addr
       @16: octets       ip_dst        [ 32b] Dest addr
       rest is application defined message body

== Web site

The current version of this software can be found at http://redshift.sourceforge.net/bit-struct.

== License

This software is distributed under the Ruby license. See http://www.ruby-lang.org.

== Author

Joel VanderWerf, mailto:vjoel@users.sourceforge.net
Copyright (c) 2005-2009, Joel VanderWerf.
