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
	['aarch64', 'aarch64-linux-musl'],
  ['armbe',   'armv5b-linux-musleabi'],
  ['armle',   'armv5l-linux-musleabi'],
  ['mips64',  'mips64-linux-muslsf'],
  ['mipsbe',  'mips-linux-muslsf'],
  ['mipsle',  'mipsel-linux-muslsf'],
  ['ppc',     'powerpc-linux-muslsf'],
  ['ppc64le', 'powerpc64le-linux-musl'],
  ['x64',     'x86_64-linux-musl'],
  ['x86',     'i486-linux-musl'],
  ['zarch',   's390x-linux-musl'],
]

arch = ''
payload = ''
scheme = ''
cwd = File::dirname(__FILE__)
template = File::read(File::join(cwd, 'linux_meterpreter_reverse.erb'))
renderer = ERB.new(template)

arches.each do |a, p|
  schemes.each do |s|
    arch = a
    payload = p
    scheme = s
    filename = File::join('modules', 'payloads', 'singles', 'linux', arch, "meterpreter_reverse_#{scheme}.rb")
    File::write(filename, renderer.result())
  end
end

`bundle exec #{File::join(cwd, 'update_payload_cached_sizes.rb')}`
