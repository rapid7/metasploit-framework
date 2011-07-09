#!/usr/bin/perl
# http://www.perl.com/CPAN-local/modules/by-module/MIME/MIME-Base64-2.06.tar.gz
# http://www.perl.com/CPAN-local/modules/by-module/SHA/SHA-1.2.tar.gz

use MIME::Base64;
use SHA;
if ("SHA-1" ne &SHA::sha_version) { die "wrong SHA version\n"; }
$sha = new SHA;

$label = "{SHA}";
$count = 1;
while(<>) {
  chomp;
  $hash = $sha->hash ($_);
  printf ("%s:%s%s:%d:%d:%s:/home/%s/:\n",
    $_, $label, encode_base64 ($hash . $salt, ""), $count, $count,
    $_, $_);
  $count++;
}
