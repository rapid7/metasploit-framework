#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

	# The operating system type determines how certain headers are set.
	@@IS_OPENBSD   = RUBY_PLATFORM.include?('openbsd')
	@@IS_BSD       = RUBY_PLATFORM.include?('bsd')
	@@IS_LINUX     = RUBY_PLATFORM.include?('linux')
	@@IS_WINDOWS   = RUBY_PLATFORM.include?('mswin')

	# Check for the pcaprub module, required to send/recv packets.
	@@HAVE_PCAPRUB = false
	begin
		require 'pcaprub'
		@@HAVE_PCAPRUB = true
	rescue ::LoadError
	end

end