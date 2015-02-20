# -*- coding: binary -*-
###
#
# This module exposes a simple method to create a file.
#
###

module Msf
module Exploit::FILEFORMAT

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('FILENAME', [ false, 'The file name.',  nil]),
      ], Msf::Exploit::FILEFORMAT
    )

    register_advanced_options(
      [
        OptBool.new('DisablePayloadHandler', [ false, "Disable the handler code for the selected payload", true ])
      ], Msf::Exploit::FILEFORMAT
    )
  end

  def file_format_filename
    datastore['FILENAME']
  end

  def file_create(data)
    fname = file_format_filename
    ltype = "exploit.fileformat.#{self.shortname}"
    full_path = store_local(ltype, nil, data, fname)
    print_good "#{fname} stored at #{full_path}"
  end

end
end
