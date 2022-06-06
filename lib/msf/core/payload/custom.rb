# -*- coding => binary -*-

#
module Msf::Payload::Custom

  def stage_payload(_opts = {})
    if datastore['SHELLCODE_FILE'].nil?
      return nil
    else
      return File.binread(datastore['SHELLCODE_FILE'])
    end
  end

  def setup_handler
    if datastore['SHELLCODE_FILE'].nil?
      fail_with(Msf::Module::Failure::BadConfig, "No SHELLCODE_FILE provided")
    else
      begin
        # read the file before we start the handler to make sure that it is valid
        test = File.binread(datastore['SHELLCODE_FILE'])
      rescue => e
        print_error("Unable to read #{datastore['SHELLCODE_FILE']}:\n#{e}")
        elog(e)
        fail_with(Msf::Module::Failure::BadConfig, "Bad SHELLCODE_FILE provided")
      end
    end
    super
  end

  def read_stage_size?
    true
  end
end
