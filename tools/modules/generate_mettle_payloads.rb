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
  ['aarch64',   'Linux', 'aarch64-linux-musl', 'Linux'],
  ['armbe',     'Linux', 'armv5b-linux-musleabi', 'Linux'],
  ['armle',     'Linux', 'armv5l-linux-musleabi', 'Linux'],
  ['mips64',    'Linux', 'mips64-linux-muslsf', 'Linux'],
  ['mipsbe',    'Linux', 'mips-linux-muslsf', 'Linux'],
  ['mipsle',    'Linux', 'mipsel-linux-muslsf', 'Linux'],
  ['ppc',       'Linux', 'powerpc-linux-muslsf', 'Linux'],
  ['ppce500v2', 'Linux', 'powerpc-e500v2-linux-musl', 'Linux'],
  ['ppc64le',   'Linux', 'powerpc64le-linux-musl', 'Linux'],
  ['x64',       'Linux', 'x86_64-linux-musl', 'Linux'],
  ['x86',       'Linux', 'i486-linux-musl', 'Linux'],
  ['zarch',     'Linux', 's390x-linux-musl', 'Linux'],
  ['x64',       'OSX',   'x86_64-apple-darwin', 'Osx'],
  ['aarch64',   'Apple_iOS',   'aarch64-iphone-darwin', ''],
  ['armle',     'Apple_iOS',   'arm-iphone-darwin', ''],
]

arch = ''
payload = ''
platform = ''
mixin = ''
scheme = ''
cwd = File::dirname(__FILE__)

arches.each do |a, pl, pa, mix|
  schemes.each do |s|
    arch = a
    platform = pl
    payload = pa
    mixin = mix
    scheme = s

    template = File::read(File::join(cwd, "meterpreter_reverse.erb"))
    renderer = ERB.new(template)
    filename = File::join('modules', 'payloads', 'singles', platform.downcase, arch, "meterpreter_reverse_#{scheme}.rb")
    File::write(filename, renderer.result())
  end
end

`bundle exec #{File::join(cwd, 'update_payload_cached_sizes.rb')}`
