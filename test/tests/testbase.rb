#!/usr/bin/env

$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '..', '..', 'lib'))

require 'rex'
require 'msf/core'
require 'msf/base'
require 'msf/ui'

$msf = Msf::Simple::Framework.create
