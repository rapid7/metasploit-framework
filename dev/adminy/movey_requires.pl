#!/usr/bin/perl -pi
use strict;

s/require '(.*?)'/"require '" . waka($1) . "'"/ge;

sub waka {
	my $required = shift;

	my @pieces = split('/', $required);
	map { $_ = old_to_new($_) } @pieces;
	my $new = join('/', @pieces);

	return $new;
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
