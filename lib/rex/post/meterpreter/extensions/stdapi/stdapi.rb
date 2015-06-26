# -*- coding: binary -*-

require 'rex/post/meeterpeter/object_aliases'
require 'rex/post/meeterpeter/extension'
require 'rex/post/meeterpeter/extensions/stdapi/constants'
require 'rex/post/meeterpeter/extensions/stdapi/tlv'
require 'rex/post/meeterpeter/extensions/stdapi/fs/dir'
require 'rex/post/meeterpeter/extensions/stdapi/fs/file'
require 'rex/post/meeterpeter/extensions/stdapi/fs/file_stat'
require 'rex/post/meeterpeter/extensions/stdapi/net/resolve'
require 'rex/post/meeterpeter/extensions/stdapi/net/config'
require 'rex/post/meeterpeter/extensions/stdapi/net/socket'
require 'rex/post/meeterpeter/extensions/stdapi/sys/config'
require 'rex/post/meeterpeter/extensions/stdapi/sys/process'
require 'rex/post/meeterpeter/extensions/stdapi/sys/registry'
require 'rex/post/meeterpeter/extensions/stdapi/sys/event_log'
require 'rex/post/meeterpeter/extensions/stdapi/sys/power'
require 'rex/post/meeterpeter/extensions/stdapi/railgun/railgun'
require 'rex/post/meeterpeter/extensions/stdapi/ui'
require 'rex/post/meeterpeter/extensions/stdapi/webcam/webcam'

module Rex
module Post
module meeterpeter
module Extensions
module Stdapi

###
#
# Standard ruby interface to remote entities for meeterpeter.  It provides
# basic access to files, network, system, and other properties of the remote
# machine that are fairly universal.
#
###
class Stdapi < Extension

  #
  # Initializes an instance of the standard API extension.
  #
  def initialize(client)
    super(client, 'stdapi')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'fs',
          'ext'  => ObjectAliases.new(
            {
              'dir'      => self.dir,
              'file'     => self.file,
              'filestat' => self.filestat
            })
        },
        {
          'name' => 'sys',
          'ext'  => ObjectAliases.new(
            {
              'config'   => Sys::Config.new(client),
              'process'  => self.process,
              'registry' => self.registry,
              'eventlog' => self.eventlog,
              'power'    => self.power
            })
        },
        {
          'name' => 'net',
          'ext'  => ObjectAliases.new(
            {
              'config'   => Rex::Post::meeterpeter::Extensions::Stdapi::Net::Config.new(client),
              'socket'   => Rex::Post::meeterpeter::Extensions::Stdapi::Net::Socket.new(client),
              'resolve'  => Rex::Post::meeterpeter::Extensions::Stdapi::Net::Resolve.new(client)
            })
        },
        {
          'name' => 'railgun',
          'ext'  => Rex::Post::meeterpeter::Extensions::Stdapi::Railgun::Railgun.new(client)
        },
        {
          'name' => 'webcam',
          'ext'  => Rex::Post::meeterpeter::Extensions::Stdapi::Webcam::Webcam.new(client)
        },
        {
          'name' => 'ui',
          'ext'  => UI.new(client)
        }

      ])
  end

  #
  # Sets the client instance on a duplicated copy of the supplied class.
  #
  def brand(klass)
    klass = klass.dup
    klass.client = self.client
    return klass
  end

  #
  # Returns a copy of the Dir class.
  #
  def dir
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Fs::Dir)
  end

  #
  # Returns a copy of the File class.
  #
  def file
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Fs::File)
  end

  #
  # Returns a copy of the FileStat class.
  #
  def filestat
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Fs::FileStat)
  end

  #
  # Returns a copy of the Process class.
  #
  def process
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Sys::Process)
  end

  #
  # Returns a copy of the Registry class.
  #
  def registry
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Sys::Registry)
  end

  #
  # Returns a copy of the EventLog class.
  #
  def eventlog
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Sys::EventLog)
  end

  #
  # Returns a copy of the Power class.
  #
  def power
    brand(Rex::Post::meeterpeter::Extensions::Stdapi::Sys::Power)
  end
end

end; end; end; end; end
