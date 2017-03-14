# -*- coding: binary -*-

module Msf
# Mixin for handling options related to remote files in SMB modules
module Exploit::Remote::SMB::Client::RemotePaths
  def initialize(info = {})
    super
    register_options(
      [
        OptString.new('RPATH', [false, 'The name of the remote file relative to the share to operate on']),
        OptPath.new('FILE_RPATHS', [false, 'A file containing a list remote files relative to the share to operate on'])
      ], self.class)
  end

  def setup
    unless (datastore['FILE_RPATHS'] && !datastore['RPATH']) || (!datastore['FILE_RPATHS'] && datastore['RPATH'])
      fail_with(::Msf::Module::Failure::BadConfig, 'One and only one of FILE_RPATHS or RPATH must be specified')
    end
  end

  def remote_paths
    if datastore['FILE_RPATHS']
      IO.readlines(datastore['FILE_RPATHS']).map(&:strip)
    elsif datastore['RPATH']
      [datastore['RPATH']]
    end
  end
end
end
