# -*- coding => binary -*-

#
module Msf::Payload::Custom

  def stage_payload(_opts = {})
    return nil if datastore['SHELLCODE_FILE'].blank?

    File.binread(datastore['SHELLCODE_FILE'])
  end

  def setup_handler
    if datastore['SHELLCODE_FILE'].blank?
      fail_with(Msf::Module::Failure::BadConfig, "No SHELLCODE_FILE provided")
    end
    begin
      # read the file before we start the handler to make sure that it is valid
      test = File.binread(datastore['SHELLCODE_FILE'])
    rescue => e
      print_error("Unable to read #{datastore['SHELLCODE_FILE']}:")
      elog("Unable to read #{datastore['SHELLCODE_FILE']}:", error: e)
      fail_with(Msf::Module::Failure::BadConfig, "Bad SHELLCODE_FILE provided")
    end
    super
  end

  def read_stage_size?
    true
  end
end
