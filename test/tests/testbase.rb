#!/usr/bin/env

$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '..', '..', 'lib'))

require 'rex'

$msf = Msf::Simple::Framework.create
