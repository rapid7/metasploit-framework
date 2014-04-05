#!/usr/bin/perl
#
#####################################################################
#
#   Written by JoMo-Kun <jmk at foofus.net> in 2007
#   and placed in the public domain.
#
#   The purpose of this script is to aid with cracking a LM/NTLM
#   challenge/response set, when part of the password is known. It
#   was written with John's NetLM/NetNTLM formats and "halflmchall"
#   Rainbow Tables in mind.
#
#   Example Scenario:
#   Let's assume you've captured LM/NTLM challenge/response set for
#   the password Cricket88!. You may be able to crack the first part
#   (i.e. CRICKET) using "Half LM" Rainbow Tables. This script will
#   use that value as a seed and attempt to crack the second part
#   (i.e. "88!") via an incremental brute. It'll then use the NetNTLM
#   response hash to crack the case-sensitive version of the entire
#   password.
#
#####################################################################

use Getopt::Long;

my $VERSION = "0.2";
my %opt;
my %data;

my $JOHN = "john";

GetOptions (
  'seed=s'      => \$opt{'seed'},
  'file=s'      => \$opt{'file'},
  'help|h'      => sub { ShowUsage(); },
);

sub showUsage {
  print "john-netntlm.pl v$VERSION\n\n";
  print "JoMo-Kun <jmk\@foofus.net>\n\n";
  print "Usage: $0 [OPTIONS]\n";
  print " $0\n";
  print "   --seed [RainbowCrack/HalfLM Response Password]\n";
  print "   --file [File Containing LM/NTLM challenge/responses (.lc format)]\n";
  print "          Ex: Domain\\User:::LM response:NTLM response:challenge";
  print "\n";
  print " Ex:\n";
  print " $0 --file capture.lc\n";
  print " $0 --seed \"GERGE!!\"--file capture.lc\n";
  print "\n";
  exit(1);
}

# Main
{
  if ( !defined($opt{'file'}) ) { &showUsage; }

  # Parse accounts to audit
  open(HAND, $opt{'file'}) || die("Failed to open response file: $opt{'file'} -- $!");
  @{ $data{'pairs'} } = <HAND>;
  close(HAND);

  # Load information for any accounts previous cracked
  print STDERR "\n\n";
  print STDERR "###########################################################################################\n";

  open (HAND, "$JOHN -format:netlm -show $opt{'file'} |") || die("Failed to execute john: $!");
  print STDERR "The following LM responses have been previously cracked:\n";
  while(<HAND>) {
    next if ( /\d+ password hashes cracked, \d+ left/ );
    last if /^$/;
    print "\t$_";
    push @{ $data{'cracked-lm'} }, $_;
  }
  close(HAND);

  print STDERR "\nThe following NTLM responses have been previously cracked:\n";
  open (HAND, "$JOHN -format:netntlm -show $opt{'file'} |") || die("Failed to execute john: $!");
  while(<HAND>) {
    next if ( /\d+ password hashes cracked, \d+ left/ );
    last if /^$/;
    print "\t$_";
    push @{ $data{'cracked-ntlm'} }, $_;
  }
  close(HAND);

  mkdir("/tmp/john.$$") || die;
  my $tmpconf = &createConf();
  my $tmpsession = "/tmp/john.$$/john.session";
  my $tmpsessionlog = "/tmp/john.$$/john.session.log";
  my $tmplog = "/tmp/john.$$/john.log";
  #print STDERR "Created temporary configuration file: $tmpconf\n";

  # Crack case-sensitive version of password
  my $tmpdict = "/tmp/john.$$/john.dict";
  #print STDERR "Created temporary dictionary file: $tmpdict\n";

  foreach $credential_set ( @{ $data{'cracked-lm'} } ) {
    my ($account,$lmpass,$bar,$netlm,$netntlm,$chall) = split(/:/, $credential_set);
    next if ( grep(/^$account:/i, @{ $data{'cracked-ntlm'} }) );

    print STDERR "\n\n";
    print STDERR "###########################################################################################\n";
    print STDERR "Performing NTLM case-sensitive crack for account: $account.\n";

    open(HAND, ">$tmpdict") || die("Failed to option file: $tmpdict -- $!");
    print HAND "$lmpass";
    close(HAND);

    open (HAND, "$JOHN -format:netntlm -config:$tmpconf -wordlist:$tmpdict -rules -user:\"$account\" -session:$tmpsession $opt{'file'} |") || die("Failed to execute john: $!");
    while(<HAND>) { print; }
    close(HAND);

    unlink $tmpdict || warn("Failed to unlink $tmpdict -- $!");
  }

  print STDERR "\n\n";
  print STDERR "###########################################################################################\n";
  print STDERR "Isolating accounts which have only had their LM response cracked.\n";

  foreach $credential_set ( @{ $data{'pairs'} } ) {
    $credential_set =~ s/\\/\\\\/g;
    my ($account,$foo,$bar,$netlm,$netntlm,$chall) = split(/:/, $credential_set);
    if (lc($netlm) eq lc($netntlm)) {
      print STDERR "LM response is not unique from NTLM response (skipping):\n\t$credential_set\n";
      push  @{ $data{'pairs-ntlm'} }, $credential_set;
    }
    elsif ( @cracked = grep(/^$account:/i, @{ $data{'cracked-ntlm'} }) ) {
      print STDERR "Account $account NTLM response previously cracked.\n";
      #print "@cracked";
    }
    else {
      print STDERR "Account $account LM response added to cracking list.\n";
      push  @{ $data{'pairs-lm'} }, $credential_set;
    }
  }

  if ( defined($opt{'seed'}) ) {
    print STDERR "\n\n";
    print STDERR "###########################################################################################\n";
    print STDERR "Testing seed password to determine whether it is the actual password.\n";
    open(HAND, ">$tmpdict") || die("Failed to option file: $tmpdict -- $!");
    print HAND $opt{'seed'};
    close(HAND);

    open (HAND, "$JOHN -format:netntlm -config:$tmpconf -wordlist:$tmpdict -rules -session:$tmpsession $opt{'file'} |") || die("Failed to execute john: $!");
    while(<HAND>) {
      print;
      next if (/^guesses: .*time: / || (/^Loaded .* password hash /) || (/^No password hashes loaded/));
      my ($account) = $_ =~ / \((.*)\)$/;

      # Remove accounts which just cracked from list
      my $i = 0;
      foreach $credential_set ( @{ $data{'pairs-lm'} } ) {
        $account =~ s/\\/_/g;
        $credential_set =~ s/\\\\/_/g;
        if ( $credential_set =~  /^$account:/ ) {
          splice(@{ $data{'pairs-lm'} }, $i, 1);
        }
        $i++;
      }
    }
    close(HAND);
    unlink $tmpdict || warn("Failed to unlink $tmpdict -- $!");

    my $tmppasswd = "/tmp/john.$$/john.passwd";
    open(HAND, ">$tmppasswd") || die("Failed to open $tmppasswd: $!");
    print HAND  @{ $data{'pairs-lm'} };
    close(HAND);

    print STDERR "\n\n";
    print STDERR "###########################################################################################\n";
    print STDERR "The hashes contained within $tmppasswd have not been cracked.\n";
    print STDERR "Executing the following (this could take a while...):\n\n";
    print STDERR "john -format:netlm -config:$tmpconf -external:HalfLM -incremental:LM -session:$tmpsession $tmppasswd\n";
    print STDERR "\n";
    print STDERR " *If the passwords successfully crack, use this script again to crack the case-sensitive password\n";
    print STDERR " without feeding a seed password\n";
    print STDERR"\n\n";

    system("$JOHN -format:netlm -config:$tmpconf -external:HalfLM -incremental:LM -session:$tmpsession $tmppasswd");
    #exec("$JOHN -format:netlm -config:$tmpconf -external:HalfLM -incremental:LM -session:$tmpsession $tmppasswd");

    unlink $tmppasswd || warn("Failed to unlink $tmppasswd -- $!");
  }
  else {
    print STDERR "\nNo seed supplied for testing.\n";
  }

  #print STDERR "Removing temporary files and directory\n";
  unlink $tmpconf, $tmplog, $tmpsession, $tmpsessionlog || warn("Failed to unlink temporary config files -- $!");
  rmdir("/tmp/john.$$") || warn("Failed to delete temporary john directory -- $!");
}

exit(0);

sub createConf {
  my $tmpconf = "/tmp/john.$$/john.conf";
  open(CONF, ">$tmpconf") || die("Failed to open $tmpconf: $!");

  # Define character keyspace
  print CONF "[Incremental:LM]\n";
  print CONF "File = \$JOHN/lanman.chr\n";
  print CONF "MinLen = 1\n";

  # John compiled for MaxLen <= 8
  if (14 - length($opt{'seed'}) > 8) {
    print CONF "MaxLen = 8\n";
  } else {
    print CONF "MaxLen = ", 14 - length($opt{'seed'}), "\n";
  }
  print CONF "CharCount = 69\n\n";

  # Add external filter to handle uncracked characters
  if ($opt{'seed'} ne "") {
    my $i; $j;
    my @seed = split(//, $opt{'seed'});

    print CONF "[List.External:HalfLM]\n";
    print CONF "void init()\n";
    print CONF "{\n";
    print CONF "  word[14] = 0;\n";
    print CONF "}\n\n";

    print CONF "void filter()\n";
    print CONF "{\n";

    my $len = length($opt{'seed'});
    for ($i = 13, $j = 13 - $len; $i>=0; $i--) {
      if ($i >= $len) {
        print CONF "  word[$i] = word[$j];\n";
        $j--;
      } else {
        print CONF "  word[$i] = \'$seed[$i]\';\n";
      }
    }

    print CONF "}\n\n";
  }

  # Add custom wordlist to utilize NTLM hash for character case cracking
  print CONF "[List.Rules:Wordlist]\n";
  print CONF ":\n";
  print CONF "-c T0Q\n";
  print CONF "-c T1QT[z0]\n";
  print CONF "-c T2QT[z0]T[z1]\n";
  print CONF "-c T3QT[z0]T[z1]T[z2]\n";
  print CONF "-c T4QT[z0]T[z1]T[z2]T[z3]\n";
  print CONF "-c T5QT[z0]T[z1]T[z2]T[z3]T[z4]\n";
  print CONF "-c T6QT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]\n";
  print CONF "-c T7QT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]\n";
  print CONF "-c T8QT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]T[z7]\n";
  print CONF "-c T9QT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]T[z7]T[z8]\n";
  print CONF "-c TAQT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]T[z7]T[z8]T[z9]\n";
  print CONF "-c TBQT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]T[z7]T[z8]T[z9]T[zA]\n";
  print CONF "-c TCQT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]T[z7]T[z8]T[z9]T[zA]T[zB]\n";
  print CONF "-c TDQT[z0]T[z1]T[z2]T[z3]T[z4]T[z5]T[z6]T[z7]T[z8]T[z9]T[zA]T[zB]T[zC]\n";

  close(CONF);

  return $tmpconf;
}
