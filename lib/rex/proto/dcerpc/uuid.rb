# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
class UUID


  @@known_uuids =
  {
    'MGMT'      => [ 'afa8bd80-7d8a-11c9-bef4-08002b102989', '2.0' ],
    'REMACT'    => [ '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57', '0.0' ],
    'SYSACT'    => [ '000001a0-0000-0000-c000-000000000046', '0.0' ],
    'LSA_DS'    => [ '3919286a-b10c-11d0-9ba8-00c04fd92ef5', '0.0' ],
    'SAMR'      => [ '12345778-1234-abcd-ef00-0123456789ac', '1.0' ],
    'MSMQ'      => [ 'fdb3a030-065f-11d1-bb9b-00a024ea5525', '1.0' ],
    'EVENTLOG'  => [ '82273fdc-e32a-18c3-3f78-827929dc23ea', '0.0' ],
    'SVCCTL'    => [ '367abb81-9844-35f1-ad32-98f038001003', '2.0' ],
    'SRVSVC'    => [ '4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0' ],
    'PNP'       => [ '8d9f4e40-a03d-11ce-8f69-08003e30051b', '1.0' ]
  }

  # Convert a UUID in binary format to the string representation
  def self.uuid_unpack(uuid_bin)
    raise ArgumentError if uuid_bin.length != 16
    sprintf("%.8x-%.4x-%.4x-%.4x-%s",
      uuid_bin[ 0, 4].unpack('V')[0],
      uuid_bin[ 4, 2].unpack('v')[0],
      uuid_bin[ 6, 2].unpack('v')[0],
      uuid_bin[ 8, 2].unpack('n')[0],
      uuid_bin[10, 6].unpack('H*')[0]
    )
  end

  # Validate a text based UUID
  def self.is? (uuid_str)
    raise ArgumentError if !uuid_str
    if uuid_str.match(/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/)
      return true
    else
      return false
    end
  end

  # Convert a UUID in string format to the binary representation
  def self.uuid_pack (uuid_str)
    raise ArgumentError if !self.is?(uuid_str)
    parts = uuid_str.split('-')
    [ parts[0].hex, parts[1].hex, parts[2].hex, parts[3].hex ].pack('Vvvn') + [ parts[4] ].pack('H*')
  end

  # Provide the common TransferSyntax UUID in packed format
  def self.xfer_syntax_uuid ()
    self.uuid_pack('8a885d04-1ceb-11c9-9fe8-08002b104860')
  end

  # Provide the common TransferSyntax version number
  def self.xfer_syntax_vers ()
    '2.0'
  end

  # Determine the UUID string for the DCERPC service with this name
  def self.uuid_by_name (name)
    if @@known_uuids.key?(name)
      @@known_uuids[name][0]
    end
  end

  # Determine the common version number for the DCERPC service with this name
  def self.vers_by_name (name)
    if @@known_uuids.key?(name)
      @@known_uuids[name][1]
    end
  end

  # Convert a string or number in float format to two unique numbers 2.0 => [2, 0]
  def self.vers_to_nums (vers)
    vers_maj = vers.to_i
    vers_min = ((vers.to_f - vers.to_i) * 10).to_i
    return vers_maj, vers_min
  end

end
end
end
end
