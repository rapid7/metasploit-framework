#!/usr/bin/perl -w
# Usage: sap_prepare.pl csv-input sap-codeB-output sap-codevnG-output
#   csv-input: XLS-exported table USH02 or USR02
#              tab-speparted e.g. column 4:username column 17:bcode column 24:codvn G
#   sap-codeB-output:   username:username<spaces>$bcode
#   sap-codevnG-output: username:Username<spaces>$codvnG
#
# (all other formats with the right column names should work)
# sap uses the username as salt. those have different length, so we needed to come up w/ our
# own format. that is: username<space-padding-to-40>$HASHCODE
#
# evil spaghetti code, but works. sorry for the eye cancer ;-)

$SALT_LENGTH = 40;

if ($#ARGV != 2) {
  die ("usage = $0 csv-input sap-codeB-output sap-codevnG-output \n");
}

open INPUT_FILE,  "$ARGV[0]" or die ("Can't open input-file ($ARGV[0])\n");
open CODEB_FILE,">>$ARGV[1]" or die ("Can't open codeb-file ($ARGV[1])\n");
open CODEG_FILE,">>$ARGV[2]" or die ("Can't open codeg-file ($ARGV[2])\n");

print "data from >>$ARGV[0]<<\nto sap-codeB-output: >>$ARGV[1]<<\n";
print "and sap-codevnG-output: >>$ARGV[2]<<\n\n";

$line = "";
$pos_bname=-1;
$pos_codeb=-1;
$pos_codeg=-1;
$count=0;

until ($line =~ /BNAME/)  {
	$line=<INPUT_FILE>;
	$count++;
}

chomp($line);
@tmp = split(/\t/, $line);

for ($i=0;$i<=$#tmp;$i++) {
	if    ($tmp[$i]=~ /BNAME/)    { $pos_bname=$i }
	elsif ($tmp[$i]=~ /BCODE/)    { $pos_codeb=$i }
	elsif ($tmp[$i]=~ /PASSCODE/) { $pos_codeg=$i }
}
print "Column: $#tmp BNAME: $pos_bname BCODE: $pos_codeb PASSCODE: $pos_codeg\n";

if (-1==$pos_bname || (-1==$pos_codeg  && -1==$pos_codeb ) ) {
	print "BNAME column not found OR both hash-columns are missing \n";
	exit 0;
}

while ($line=<INPUT_FILE>) {
	$count++;
	chomp($line);
	@tmp = split(/\t/, $line);
	if ($#tmp<$pos_bname || ($#tmp<$pos_codeb && $#tmp<$pos_codeg)) {
		print "******** line $count in csv file has the wrong format ********\n";
		next;
	}
	if ($pos_codeg!=-1 && $tmp[$pos_codeg]=~/[a-zA-Z0-9]/) {  # both hashes
 		print "username: $tmp[$pos_bname] codeB: $tmp[$pos_codeb] codeG: $tmp[$pos_codeg] \n";
		$strN = $tmp[$pos_bname];
		$strSALT = "$strN"." "x($SALT_LENGTH-length($tmp[$pos_bname]));
		$strB = "$tmp[$pos_codeb]";
		$strG = "$tmp[$pos_codeg]";
		print CODEB_FILE "$strN:$strSALT\$$strB\n";
		print CODEG_FILE "$strN:$strSALT\$$strG\n";
	}
	elsif ($pos_codeb!=-1 &&  $tmp[$pos_codeb]=~/[a-zA-Z0-9]/ ) { # only bcode
		print "username: $tmp[$pos_bname] codeB: $tmp[$pos_codeb] \n";
		$strN = $tmp[$pos_bname];
		$strSALT = "$strN"." "x($SALT_LENGTH-length($tmp[$pos_bname]));
		$strB = "$tmp[$pos_codeb]";
		print CODEB_FILE "$strN:$strSALT\$$strB\n";
	}
	else {
		print "******** line $count in csv file has the wrong format ********\n";
	}
}

close INPUT_FILE;
close CODEB_FILE;
close CODEG_FILE;

print "\nDone!\n";
exit 0;


