#!/usr/bin/perl

$i=1;

while(<>) {
	chomp;
	if(/^$/) {
		if($object{"uid"} ne "") {
			print $object{"uid"}.":";
			print $object{"userPassword"} ne "" ? $object{"userPassword"} : "*";
			print ":";
			print $i.":";
			print $i.":";
			print $object{"cn"}.":";
			print $object{"homeDirectory"} ne "" ? $object{"homeDirectory"} : "/";
			print ":/bin/sh\n";
		}
		%object = ();
		$i++;
		next;
	}

	($lhs, $rhs) = split(/: /);
	$object{$lhs} = $rhs;
}
