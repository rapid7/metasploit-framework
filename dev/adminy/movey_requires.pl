#!/usr/bin/perl
use strict;

while(<STDIN>) {
	my $line = $_;

	if($line =~ /require '(.*?)'/) {
		my $required = $1;

		my @pieces = split('/', $required);
		map { $_ = old_to_new($_) } @pieces;
		my $new = join('/', @pieces);

		print "$required -> $new\n";
	}
}

sub old_to_new {
	my $name = shift;

	if(uc($name) eq $name) {
		return(lc($name));
	}

	$name =~ s/^([A-Z])/lc($1)/ge;
	$name =~ s/([A-Z])/"_" . lc($1)/ge;

	return($name);
}
