# RubySMB

[![Build Status](https://travis-ci.org/rapid7/ruby_smb.svg?branch=master)](https://travis-ci.org/rapid7/ruby_smb)
[![Code Climate](https://codeclimate.com/github/rapid7/ruby_smb.png)](https://codeclimate.com/github/rapid7/ruby_smb)
[![Coverage Status](https://coveralls.io/repos/github/rapid7/ruby_smb/badge.svg?branch=master)](https://coveralls.io/github/rapid7/ruby_smb?branch=master)

A native Ruby implementation of the SMB Protocol Family. It currently supports
 1. [[MS-SMB]](https://msdn.microsoft.com/en-us/library/cc246231.aspx)
 1. [[MS-SMB2]](http://msdn.microsoft.com/en-us/library/cc246482.aspx)

This library currently include both a client level, and packet level support. A user can parse and manipulate raw SMB packets, or use the simple client to perform SMB operations.

See the Wiki for more information on this project's long-term goals, style guide, and developer tips.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ruby_smb'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ruby_smb

## Usage

### Defining a packet

All packets are implemented in a declarative style with BinData. Nested data
structures are used where appropriate to give users an easy method of adjusting
data.

#### SMB1
SMB1 Packets are made up of three basic components:
 1. **The SMB Header** - This is a standard SMB Header. All SMB1 packets use the same SMB header.
 1. **The Parameter Block** - This is where function parameters are passed across the wire in the packet. Parameter Blocks will always
 have a 'Word Count' field that gives the size of the Parameter Block in words(2-bytes)
 1. **The Data Block** - This is the data section of the packet. the Data Block will always have a 'byte count' field that gives the size of
 the Data block in bytes.

The SMB Header can always just be declared as a field in the BinData DSL for the packet class, because its structure never changes.
For the ParameterBlock and DataBlocks, we always define subclasses for this particular packet. They inherit the 'Word Count' and
'Byte Count' fields, along with the auto-calculation routines for those fields, from their ancestors. Any other fields are then
defined in our subclass before we start the DSL declarations for the packet.

Example:

```ruby
module RubySMB
  module SMB1
    module Packet

      # This class represents an SMB1 TreeConnect Request Packet as defined in
      # [2.2.4.7.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246330.aspx)
      class TreeConnectRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {TreeConnectRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          and_x_block          :andx_block
          tree_connect_flags   :flags
          uint16               :password_length, label: 'Password Length', initial_value: 0x01
        end

        class DataBlock < RubySMB::SMB1::DataBlock
          stringz  :password, label: 'Password Field', initial_value: '',    length: lambda { self.parent.parameter_block.password_length }
          stringz  :path,     label: 'Resource Path'
          stringz  :service,  label: 'Resource Type',  initial_value: '?????'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
        end

      end
    end
  end
end
```

#### SMB2

SMB2 Packets are far simpler than their older SMB1 counterparts. We still abstract out the SMB2 header since it is the same
structure used for every packet. Beyond that, the SMB2 packet is relatively flat in comparison to SMB1.

Example:
```ruby
module RubySMB
  module SMB2
    module Packet

      # An SMB2 TreeConnectRequest Packet as defined in
      # [2.2.9 SMB2 TREE_CONNECT Request](https://msdn.microsoft.com/en-us/library/cc246567.aspx)
      class TreeConnectRequest < RubySMB::GenericPacket
        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 9
        uint16       :flags,          label: 'Flags',          initial_value: 0x00
        uint16       :path_offset,    label: 'Path Offset',    initial_value: 0x48
        uint16       :path_length,    label: 'Path Length',    initial_value: lambda { self.path.length }
        string       :path,           label: 'Path Buffer'

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::TREE_CONNECT
        end

        def encode_path(path)
          self.path = path.encode("utf-16le")
        end
      end
    end
  end
end
```

### Using a Packet class

#### Manually
You can instantiate an instance of a particular packet class, and then reach into the data structure to set or read explicit
values in a fairly straightforward manner.

Example:
```ruby
2.3.3 :001 > packet = RubySMB::SMB1::Packet::TreeConnectRequest.new
 => {:smb_header=>{:protocol=>4283649346, :command=>117, :nt_status=>0, :flags=>{:reply=>0, :opbatch=>0, :oplock=>0, :canonicalized_paths=>1, :case_insensitive=>1, :reserved=>0, :buf_avail=>0, :lock_and_read_ok=>0}, :flags2=>{:reserved1=>0, :is_long_name=>0, :reserved2=>0, :signature_required=>0, :compressed=>0, :security_signature=>0, :eas=>0, :long_names=>1, :unicode=>0, :nt_status=>1, :paging_io=>1, :dfs=>0, :extended_security=>0, :reparse_path=>0}, :pid_high=>0, :security_features=>"\x00\x00\x00\x00\x00\x00\x00\x00", :reserved=>0, :tid=>0, :pid_low=>0, :uid=>0, :mid=>0}, :parameter_block=>{:word_count=>4, :andx_block=>{:andx_command=>255, :andx_reserved=>0, :andx_offset=>0}, :flags=>{:reserved=>0, :extended_response=>1, :extended_signature=>0, :reserved2=>0, :disconnect=>0, :reserved3=>0, :reserved4=>0}, :password_length=>1}, :data_block=>{:byte_count=>8, :password=>"", :path=>"", :service=>"?????"}}
2.3.3 :002 > packet.parameter_block
 => {:word_count=>4, :andx_block=>{:andx_command=>255, :andx_reserved=>0, :andx_offset=>0}, :flags=>{:reserved=>0, :extended_response=>1, :extended_signature=>0, :reserved2=>0, :disconnect=>0, :reserved3=>0, :reserved4=>0}, :password_length=>1}
2.3.3 :003 > packet.parameter_block.flags
 => {:reserved=>0, :extended_response=>1, :extended_signature=>0, :reserved2=>0, :disconnect=>0, :reserved3=>0, :reserved4=>0}
2.3.3 :004 > packet.parameter_block.flags.extended_signature = 1
 => 1
2.3.3 :005 > packet.parameter_block.flags
 => {:reserved=>0, :extended_response=>1, :extended_signature=>1, :reserved2=>0, :disconnect=>0, :reserved3=>0, :reserved4=>0}
2.3.3 :006 >
2.3.3 :006 > packet.data_block.password = 'guest'
 => "guest"
2.3.3 :007 > packet.data_block.password
 => "guest"
2.3.3 :008 > packet.data_block
 => {:byte_count=>13, :password=>"guest", :path=>"", :service=>"?????"}
2.3.3 :009 >
```

You can also pass field/value pairs into the packet constructor as arguments, prefilling out certain fields
if you wish.

Example:
```ruby
2.3.3 :017 > packet = RubySMB::SMB2::Packet::TreeConnectRequest.new(path:'test')
 => {:smb2_header=>{:protocol=>4266872130, :structure_size=>64, :credit_charge=>0, :nt_status=>0, :command=>0, :credits=>0, :flags=>{:reserved3=>0, :signed=>0, :related_operations=>0, :async_command=>0, :reply=>0, :reserved2=>0, :reserved1=>0, :replay_operation=>0, :dfs_operation=>0}, :next_command=>0, :message_id=>0, :process_id=>65279, :tree_id=>0, :session_id=>0, :signature=>"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}, :structure_size=>9, :flags=>0, :path_offset=>72, :path_length=>4, :path=>"test"}
2.3.3 :018 > packet.path
 => "test"
```

#### Reading from a Binary Blob

Sometimes you need to read a binary blob and apply one of the packet structures to it.
For example, when you are reading a response packet off of the wire, you will need to read the raw response
string into an actual packet class. This is done using the #read class method.

```ruby
2.3.3 :014 > blob = "\xFFSMB+\x00\x00\x00\x00\x98\x01`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
 => "\xFFSMB+\u0000\u0000\u0000\u0000\x98\u0001`\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000\u0000\u0000\u0000"
2.3.3 :015 > packet = RubySMB::SMB1::Packet::EchoResponse.read(blob)
 => {:smb_header=>{:protocol=>4283649346, :command=>43, :nt_status=>0, :flags=>{:reply=>1, :opbatch=>0, :oplock=>0, :canonicalized_paths=>1, :case_insensitive=>1, :reserved=>0, :buf_avail=>0, :lock_and_read_ok=>0}, :flags2=>{:reserved1=>0, :is_long_name=>0, :reserved2=>0, :signature_required=>0, :compressed=>0, :security_signature=>0, :eas=>0, :long_names=>1, :unicode=>0, :nt_status=>1, :paging_io=>1, :dfs=>0, :extended_security=>0, :reparse_path=>0}, :pid_high=>0, :security_features=>"\x00\x00\x00\x00\x00\x00\x00\x00", :reserved=>0, :tid=>0, :pid_low=>0, :uid=>0, :mid=>0}, :parameter_block=>{:word_count=>1, :sequence_number=>0}, :data_block=>{:byte_count=>0, :data=>""}}
2.3.3 :016 >
```

#### Outputting to a Binary Blob
Any structure or packet in rubySMB can also be output back into a binary blob using
BinData's #to_binary_s method.

Example:
```ruby
2.3.3 :012 > packet = RubySMB::SMB1::Packet::EchoResponse.new
 => {:smb_header=>{:protocol=>4283649346, :command=>43, :nt_status=>0, :flags=>{:reply=>1, :opbatch=>0, :oplock=>0, :canonicalized_paths=>1, :case_insensitive=>1, :reserved=>0, :buf_avail=>0, :lock_and_read_ok=>0}, :flags2=>{:reserved1=>0, :is_long_name=>0, :reserved2=>0, :signature_required=>0, :compressed=>0, :security_signature=>0, :eas=>0, :long_names=>1, :unicode=>0, :nt_status=>1, :paging_io=>1, :dfs=>0, :extended_security=>0, :reparse_path=>0}, :pid_high=>0, :security_features=>"\x00\x00\x00\x00\x00\x00\x00\x00", :reserved=>0, :tid=>0, :pid_low=>0, :uid=>0, :mid=>0}, :parameter_block=>{:word_count=>1, :sequence_number=>0}, :data_block=>{:byte_count=>0, :data=>""}}
2.3.3 :013 > packet.to_binary_s
 => "\xFFSMB+\x00\x00\x00\x00\x98\x01`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
```
### Using the Client

Sitting on top of the packet layer in RubySMB is the RubySMB::Client. This is the level msot users will interact with.
It provides fairly simple conveience methods for performing SMB actions. It handles the creation, sending and receiving of packets
for the user, relying on reasonable defaults in many cases.

#### Negotiation

The RubySMB Client is capabale of multi-protocol negotiation. The user simply specifies whether SMB1 and/or SMB2 should be supported, and
the client will negotiate the propper protocol and dialect behind the scenes.

In the below example, we tell the client that both SMb1 and SMB2 should be supported. The Client will then Negotiate with the
server on which version should be used. The user does not have to ever worry about which version was negotiated.
Example:
```ruby
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: 'msfadmin', password: 'msfadmin')
  client.negotiate
```

#### Authentication

Authentication is achieved via the [ruby ntlm gem](https://rubygems.org/gems/rubyntlm). While the client
will not currently attempt older basic authentication on its own, it will attempt an anonymous login, if no
user credentials are supplied:

Authenticated Example:
```ruby
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: 'msfadmin', password: 'msfadmin')
  client.negotiate
  client.authenticate
```

Anonymous Example:
```ruby
      sock = TCPSocket.new address, 445
      dispatcher = RubySMB::Dispatcher::Socket.new(sock)

      client = RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: '', password: '')
      client.negotiate
      client.authenticate
```

#### Connecting to a Tree

While there is one Client, that has branching code-paths for SMB1 and SMB2, once you connect to a
Tree you will be given a protocol specific Tree object. This Tree object will be responsible for all file operations
that are to be conducted on that Tree.

In the below example we see a simple script to connect to a remote Tree, and list all files in a given sub-directory.
Example:
```ruby
      sock = TCPSocket.new address, 445
      dispatcher = RubySMB::Dispatcher::Socket.new(sock)

      client = RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: 'msfadmin', password: 'msfadmin')
      client.negotiate
      client.authenticate

      begin
        tree = client.tree_connect('TEST_SHARE')
        puts "Connected to #{path} successfully!"
      rescue StandardError => e
        puts "Failed to connect to #{path}: #{e.message}"
      end

      files = tree.list(directory: 'subdir1')

      files.each do |file|
        create_time = file.create_time.to_datetime.to_s
        access_time = file.last_access.to_datetime.to_s
        change_time = file.last_change.to_datetime.to_s
        file_name   = file.file_name.encode("UTF-8")

        puts "FILE: #{file_name}\n\tSIZE(BYTES):#{file.end_of_file}\n\tSIZE_ON_DISK(BYTES):#{file.allocation_size}\n\tCREATED:#{create_time}\n\tACCESSED:#{access_time}\n\tCHANGED:#{change_time}\n\n"
      end
```


## Developer tips
You'll want to have Wireshark and perhaps a tool like Impacket (which provides a small SMB client in one of its examples) installed to help with your work:

### Wireshark
- `sudo apt-get install wireshark`
- `sudo dpkg-reconfigure wireshark-common`
- `sudo addgroup wireshark`
- `sudo usermod -a -G wireshark <USERNAME>`

### Impacket
- `sudo apt-get install python-setuptools`
- `sudo easy_install pyasn1 pycrypto`
- Download from GitHub (https://github.com/coresecurity/impacket)
- `sudo python setup.py install`
- `cd examples && python smbclient.py <USER>:<PASS>@<WINDOWS HOST IP>`



## License

`ruby_smb` is released under a 3-clause BSD license. See [LICENSE.txt](LICENSE.txt) for full text.


## Contributing

1. Fork it ( https://github.com/rapid7/ruby_smb/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
