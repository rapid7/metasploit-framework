# -*- coding => binary -*-

#
module Msf::Payload::Custom

  def stage_payload(_opts = {})
    print_line('Trying to stage Payload')
    unless datastore['SHELLCODE_FILE'].nil?
      shellcode = File.binread(datastore['SHELLCODE_FILE'])
      if datastore['PrependSize']

        return [ shellcode.length ].pack('V') + shellcode
      else
        return shellcode
      end
    end
  end

  def handle_intermediate_stage(conn, payload)
    if( self.module_info['Stager']['RequiresMidstager'] == false ) && datastore['PrependSize']
      print_status("Skipping sending the payload length a second time")
      return false
    end

    super
  end

  def read_stage_size?
    true
  end
end
