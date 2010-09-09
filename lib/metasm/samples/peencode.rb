#!/usr/bin/env ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm'
$opts = { :execlass => Metasm::PE }
$opts[:srctype] = 'c' if ARGV.empty?
load File.join(File.dirname(__FILE__), 'exeencode.rb')

__END__
int MessageBoxA(int, char*, char*, int);
void ExitProcess(int);
void main(void)
{
	MessageBoxA(0, "kikoo", "lol", 0);
	ExitProcess(0);
}
