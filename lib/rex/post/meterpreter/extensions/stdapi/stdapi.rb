# -*- coding: binary -*-

require 'rex/post/meterpreter/object_aliases'
require 'rex/post/meterpreter/extension'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/fs/dir'
require 'rex/post/meterpreter/extensions/stdapi/fs/file'
require 'rex/post/meterpreter/extensions/stdapi/fs/file_stat'
require 'rex/post/meterpreter/extensions/stdapi/fs/mount'
require 'rex/post/meterpreter/extensions/stdapi/net/resolve'
require 'rex/post/meterpreter/extensions/stdapi/net/config'
require 'rex/post/meterpreter/extensions/stdapi/net/socket'
require 'rex/post/meterpreter/extensions/stdapi/sys/config'
require 'rex/post/meterpreter/extensions/stdapi/sys/process'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry'
require 'rex/post/meterpreter/extensions/stdapi/sys/event_log'
require 'rex/post/meterpreter/extensions/stdapi/sys/power'
require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'
require 'rex/post/meterpreter/extensions/stdapi/ui'
require 'rex/post/meterpreter/extensions/stdapi/webcam/webcam'
require 'rex/post/meterpreter/extensions/stdapi/mic/mic'
require 'rex/post/meterpreter/extensions/stdapi/corrm/apps'
require 'rex/post/meterpreter/extensions/stdapi/audio_output/audio_output'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# Standard ruby interface to remote entities for meterpreter.  It provides
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
              'filestat' => self.filestat,
              'mount'    => Fs::Mount.new(client)
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
              'config'   => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Config.new(client),
              'socket'   => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Socket.new(client),
              'resolve'  => Rex::Post::Meterpreter::Extensions::Stdapi::Net::Resolve.new(client)
            })
        },
        {
          'name' => 'railgun',
          'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Railgun.new(client)
        },
        {
          'name' => 'webcam',
          'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::Webcam::Webcam.new(client)
        },
        {
          'name' => 'mic',
          'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::Mic::Mic.new(client)
        },
        {
          'name' => 'audio_output',
          'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::AudioOutput::AudioOutput.new(client)
        },
        {
          'name' => 'ui',
          'ext'  => UI.new(client)
        },
        {
          'name' => 'apps', # => to use like that (client.apps.app_install) => "apps"
          'ext'  => Rex::Post::Meterpreter::Extensions::Stdapi::CorrM::Apps.new(client)
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
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Fs::Dir)
  end

  #
  # Returns a copy of the File class.
  #
  def file
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File)
  end

  #
  # Returns a copy of the FileStat class.
  #
  def filestat
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Fs::FileStat)
  end

  #
  # Returns a copy of the Process class.
  #
  def process
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process)
  end

  #
  # Returns a copy of the Registry class.
  #
  def registry
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Registry)
  end

  #
  # Returns a copy of the EventLog class.
  #
  def eventlog
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::EventLog)
  end

  #
  # Returns a copy of the Power class.
  #
  def power
    brand(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Power)
  end
end

end; end; end; end; end
