# -*- coding: binary -*-

module Msf
# Mixin for handling options related to local files in SMB modules
module Exploit::Remote::SMB::Client::LocalPaths
  def initialize(info = {})
    super
    register_options(
      [
        OptString.new('LPATH', [false, 'The path of the local file to utilize']),
        OptPath.new('FILE_LPATHS', [false, 'A file containing a list of local files to utilize'])
      ], self.class)
  end

  def setup
    unless (datastore['FILE_LPATHS'] && !datastore['LPATH']) || (!datastore['FILE_LPATHS'] && datastore['LPATH'])
      fail_with(::Msf::Module::Failure::BadConfig, 'One and only one of FILE_LPATHS or LPATH must be specified')
    end
  end

  def local_paths
    if datastore['FILE_LPATHS']
      IO.readlines(datastore['FILE_LPATHS']).map(&:strip)
    elsif datastore['LPATH']
      [datastore['LPATH']]
    end
  end
end
end
