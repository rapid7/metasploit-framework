#!/usr/bin/perl
use strict;


foreach my $f ('atime', 'blockdev?', 'chardev?', 'ctime', 'directory?',
  'executable?', 'executable_real?', 'file?', 'ftype', 'grpowned?',
  'mtime', 'owned?', 'pipe?', 'readable?', 'readable_real?', 'setuid?',
  'setgid?', 'size', 'socket?', 'sticky?', 'symlink?', 'writeable?',
  'writeable_real?', 'zero?') {

	my $t = "\t";
	print "${t}def File.$f(name)\n\t${t}stat(name).$f\n${t}end\n";
}
