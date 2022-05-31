# -*- coding => binary -*-

#
module Msf::Payload::Custom

  def stage_payload(_opts = {})
    if datastore['SHELLCODE_FILE'].nil?
      print_error("SHELLCODE_FILE is nil; nothing to stage.")
    else
      shellcode = File.binread(datastore['SHELLCODE_FILE'])
      if datastore['PrependSize']
        return [ shellcode.length ].pack('V') + shellcode
      else
        return shellcode
      end
    end
    return nil
  end

  def handle_intermediate_stage(conn, payload)
    if( self.module_info['Stager']['RequiresMidstager'] == false ) && datastore['PrependSize']
      print_status("Skipping sending the payload length a second time")
      return false
    end
    print_line("handle_intermediate_stager")

    super
  end

  def read_stage_size?
    true
  end
end
