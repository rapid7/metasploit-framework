#!/usr/bin/perl

use Net::LDAP;

$server = $ARGV[0];
$password = $ARGV[1];

$ldap = Net::LDAP->new($server) || die "$@";
$ldap->bind("cn=Directory Manager", password => $password) || die "$@";
$search = $ldap->search(base => "o=test",
        scope => "subtree",
        filter => "(uid=*)");

$search->code && die $search->error;

$i=0;
foreach $user ($search->all_entries) {
  @uid=$user->get("uid");
  @pass=$user->get("userpassword");
  print $uid[0].":".$pass[0].":".
    $i.":".$i.":/".$uid[0].":\n";
}
$ldap->unbind();
