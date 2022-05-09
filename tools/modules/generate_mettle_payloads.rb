#!/usr/bin/env ruby

#
# This script generates Mettle payload wrappers
#

require 'erb'

schemes = [
  'tcp',
  'http',
  'https'
]

arch_list = [
  { arch: 'aarch64',   platform: 'Linux', payload: 'aarch64-linux-musl', mixins: ['Msf::Payload::Linux'] },
  { arch: 'armbe',     platform: 'Linux', payload: 'armv5b-linux-musleabi', mixins: ['Msf::Payload::Linux'] },
  { arch: 'armle',     platform: 'Linux', payload: 'armv5l-linux-musleabi', mixins: ['Msf::Payload::Linux'] },
  { arch: 'mips64',    platform: 'Linux', payload: 'mips64-linux-muslsf', mixins: ['Msf::Payload::Linux'] },
  { arch: 'mipsbe',    platform: 'Linux', payload: 'mips-linux-muslsf', mixins: ['Msf::Payload::Linux'] },
  { arch: 'mipsle',    platform: 'Linux', payload: 'mipsel-linux-muslsf', mixins: ['Msf::Payload::Linux'] },
  { arch: 'ppc',       platform: 'Linux', payload: 'powerpc-linux-muslsf', mixins: ['Msf::Payload::Linux'] },
  { arch: 'ppce500v2', platform: 'Linux', payload: 'powerpc-e500v2-linux-musl', mixins: ['Msf::Payload::Linux'] },
  { arch: 'ppc64le',   platform: 'Linux', payload: 'powerpc64le-linux-musl', mixins: ['Msf::Payload::Linux'] },
  { arch: 'x64',       platform: 'Linux', payload: 'x86_64-linux-musl', mixins: ['Msf::Payload::Linux'] },
  { arch: 'x86',       platform: 'Linux', payload: 'i486-linux-musl', mixins: ['Msf::Payload::Linux'] },
  { arch: 'zarch',     platform: 'Linux', payload: 's390x-linux-musl', mixins: ['Msf::Payload::Linux'] },
  { arch: 'x64',       platform: 'OSX',   payload: 'x86_64-apple-darwin', mixins: ['Msf::Payload::Osx'] },
  { arch: 'aarch64',   platform: 'Apple_iOS',   payload: 'aarch64-iphone-darwin', mixins: [] },
  { arch: 'armle',     platform: 'Apple_iOS',   payload: 'arm-iphone-darwin', mixins: [] },
]

arch = ''
payload = ''
platform = ''
mixins = ''
scheme = ''
cwd = File::dirname(__FILE__)

arch_list.each do |arch_hash|
  schemes.each do |s|
    arch = arch_hash[:arch]
    platform = arch_hash[:platform]
    payload = arch_hash[:payload]
    mixins = arch_hash[:mixins].join("\n  include ")
    scheme = s

    template = File::read(File::join(cwd, "meterpreter_reverse.erb"))
    renderer = ERB.new(template)
    filename = File::join('modules', 'payloads', 'singles', platform.downcase, arch, "meterpreter_reverse_#{scheme}.rb")
    File::write(filename, renderer.result())
  end
end

`bundle exec #{File::join(cwd, 'update_payload_cached_sizes.rb')}`
