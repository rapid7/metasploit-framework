#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/core'
require 'msf/base'
require 'msf/ui'

framework = Msf::Simple::Framework.create

Rex::Ui::Text::IrbShell.new(binding).run
