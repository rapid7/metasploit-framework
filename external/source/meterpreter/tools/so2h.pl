#!/usr/bin/perl -w 

if ($#ARGV != 1) {
  print "so2h.pl <filename.so> <headername>\n";
  exit 1;
} 

my $success;
my $number_read;
my $buffer;
my $is_compressed = 0;
my $compressedname = $ARGV[0];
my $uncompressedsize;
my $compressedsize;

$success = open INPUT, "file -bi  $ARGV[0]|";
unless ($success) { 
  die "failed to open input from file \n"; 
  exit 1; 
} 

$number_read = read(INPUT, $buffer, 32); 
if ($buffer =~ "application/x-gzip") {
  $is_compressed = 1;
#
# determine file size
#
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
      $atime,$mtime,$ctime,$blksize,$blocks)
    = stat($ARGV[0]);
  $compressedsize = $size;
  
#
# figure out how big the file is uncompressed
#
  my @pathlist = split('/', $ARGV[0]);
  my $filename = $pathlist[$#pathlist];
  $uncompressedname = "/tmp/$filename";
  system("gunzip -c $ARGV[0] > $uncompressedname");
  ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
   $atime,$mtime,$ctime,$blksize,$blocks)
    = stat($uncompressedname);
  $uncompressedsize = $size;
  unlink($uncompressedname);
} else {
#
# how big is original uncompressed file?
#
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
      $atime,$mtime,$ctime,$blksize,$blocks)
    = stat($ARGV[0]);
  $uncompressedsize = $size;

#
# compress file and determine its size
#
  my @pathlist = split('/', $ARGV[0]);
  my $filename = $pathlist[$#pathlist];

  $compressedname = "/tmp/$filename.gz";
  system("gzip -nfc $ARGV[0] > $compressedname");
  ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
      $atime,$mtime,$ctime,$blksize,$blocks)
    = stat($compressedname);
  $compressedsize = $size;

}

close INPUT;

$success = open INPUT, "$compressedname";
unless ($success) {
  die "failed to open input file $compressedname\n";
  exit 1;
}
$success = open OUTPUT, ">$ARGV[1].h";
unless ($success) {
  print "failed to open output\n";
  exit 1;
}


my $license = <<END;
/**************************************************************************

Copyright (c) 2009, Metasploit Project
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Neither the name of the Metasploit Project nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN22
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


***************************************************************************/
END
print OUTPUT "$license\n";


my $binary;
my $neednewline = 0;

print OUTPUT "#define U (unsigned char)\n\n"; 

print OUTPUT "#define $ARGV[1]_size  $uncompressedsize\n";
print OUTPUT "#define $ARGV[1]_length  $compressedsize\n";
print OUTPUT "static unsigned char $ARGV[1]" . "[$compressedsize]" . " = {\n";
my $i;

for ($i = 0; $i < $compressedsize - 3; $i += 4) {
  $number_read = read(INPUT, $binary, 4);
  my ($a, $b, $c, $d) = unpack("C C C C", $binary);
  $buf = sprintf("\tU 0x%02X, U 0x%02X, U 0x%02X, U 0x%02X, \n", $a, $b, $c, $d);
  print OUTPUT $buf;
}

if ($i > 0) {
  print OUTPUT "\t";
  $neednewline = 1;  
}
for (; $i < $compressedsize; $i += 1) {
  $number_read = read(INPUT, $binary, 1);
  my $a = unpack("C", $binary);
  $buf = sprintf("U 0x%02X, ", $a);
  print OUTPUT $buf;
}

if ($neednewline) {
  print OUTPUT "\n";
} 
print OUTPUT "};\n";

# unlink temporary compressed file

if ($is_compressed == 0) {
  unlink($compressedname);
}
