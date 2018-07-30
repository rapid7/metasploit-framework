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

arches = [
  ['aarch64',   'Linux', 'aarch64-linux-musl'],
  ['armbe',     'Linux', 'armv5b-linux-musleabi'],
  ['armle',     'Linux', 'armv5l-linux-musleabi'],
  ['mips64',    'Linux', 'mips64-linux-muslsf'],
  ['mipsbe',    'Linux', 'mips-linux-muslsf'],
  ['mipsle',    'Linux', 'mipsel-linux-muslsf'],
  ['ppc',       'Linux', 'powerpc-linux-muslsf'],
  ['ppce500v2', 'Linux', 'powerpc-e500v2-linux-musl'],
  ['ppc64le',   'Linux', 'powerpc64le-linux-musl'],
  ['x64',       'Linux', 'x86_64-linux-musl'],
  ['x86',       'Linux', 'i486-linux-musl'],
  ['zarch',     'Linux', 's390x-linux-musl'],
  ['x64',       'OSX',   'x86_64-apple-darwin'],
  ['aarch64',   'Apple_iOS',   'aarch64-iphone-darwin'],
]

arch = ''
payload = ''
platform = ''
scheme = ''
cwd = File::dirname(__FILE__)

arches.each do |a, pl, pa|
  schemes.each do |s|
    arch = a
    platform = pl
    payload = pa
    scheme = s

    template = File::read(File::join(cwd, "meterpreter_reverse.erb"))
    renderer = ERB.new(template)
    filename = File::join('modules', 'payloads', 'singles', platform.downcase, arch, "meterpreter_reverse_#{scheme}.rb")
    File::write(filename, renderer.result())
  end
end

`bundle exec #{File::join(cwd, 'update_payload_cached_sizes.rb')}`
