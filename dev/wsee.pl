#!/usr/bin/perl
use strict;

my $total   = 0;
my $blank   = 0;
my $comment = 0;

while(<STDIN>) {
	my $line = $_;
	chomp($line);

	$total++;

	if($line =~ /^\s*$/) {
		$blank++;
	}
	elsif($line =~ /^\s*#/) {
		$comment++;
	}
}

my $other = $total - $blank - $comment;

printf("Total:    %4d\n", $total);

if($ARGV[0] eq '-noblank') {
	$total -= $blank;
}

printf("Blank:    %4d  ( %.2f%% )\n", $blank, $blank / $total * 100);
printf("Comments: %4d  ( %.2f%% )\n", $comment, $comment / $total * 100);
printf("Other:    %4d  ( %.2f%% )\n", $other, $other / $total * 100);

