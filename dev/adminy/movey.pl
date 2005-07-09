#/usr/bin/perl
use strict;

die if @ARGV != 1;

move($ARGV[0]);

sub old_to_new {
	my $name = shift;

	$name =~ s/^([A-Z])/lc($1)/ge;
	$name =~ s/([A-Z])/"_" . lc($1)/ge;

	return($name);
}

sub move {
	my $dir = shift;
	my @entries;
	
	opendir(DIR, $dir) || die "Can't open $dir: $!\n";
	@entries = readdir(DIR);
	closedir(DIR);

	foreach my $entry (@entries) {
		next if($entry eq 'Attic' || $entry =~ /^\./);

		my $path = $dir . '/' . $entry;
		my $newpath = $dir . '/' . old_to_new($entry);

		if(-d $path) {
			move($path);
		}

		print "$path -> $newpath\n";
		rename($path, $newpath) || die("BAH!");

	}
}
