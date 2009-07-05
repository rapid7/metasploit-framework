#!/usr/bin/perl
###############

##
#         Name: build
#       Author: H D Moore <hdm [at] metasploit.com>
#  Description: Command-line tool for building/extracting asm payloads
#      License: GPL / Perl Artistic
##


my $name = shift();

if (! $name || $name =~ /\./) { print STDERR "Usage: $0 <name>\n"; exit(0); }

if ($name eq 'clean') {
    system("rm -f *.bin *.exe *.c *.elf");
    exit(0);
}


# Compile the asm
unlink("$name.bin");
system("nasm -f bin -O3 -o $name.bin $name.asm");

if (! -f "$name.bin") {
    exit(0);
}

# Load binary
my $bindata;
open(X, "<$name.bin") || exit(0);
$bindata = join('',<X>);
close(X);

print "# Length: " . length($bindata) . " bytes\n";


# Print out common offsets into the payload data   
my $suffix;
my $port = index($bindata, pack("n", 8721));
if ($port != -1)  { 
    print "# Port: $port\n"; 
}

my $host = index($bindata, gethostbyname("127.0.0.1"));
if ($host != -1) {
    print "# Host: $host\n"; 
}

my $psize = index($bindata, pack("L", 0x12345678));
if ($psize != -1) {  
    print "# Size: $psize\n";
}

my $pstart = index($bindata, pack("L", 0x13370000));
if ($pstart != -1) {
    print "# Start: $pstart\n";
}

my $pstart = index($bindata, pack("L", 0x11223344));
if ($pstart != -1) {
    print "# Alloc: $pstart\n";
}

my $pstart = index($bindata, pack("L", 0x73e2d87e));
if ($pstart != -1) {  
    print "# ExitProcess: $pstart\n";
}

my $pstart = index($bindata, pack("L", 0x4cf079fa));
if ($pstart != -1) { 
    print "# PayloadLen: $pstart\n";
}

my $pstart = index($bindata, "\x8d\x77\x15");
if ($pstart != -1) {
    $pstart+=2; 
    print "# FileStart: $pstart\n";
}

my $pstart = index($bindata, "\x88\x4f\x1a");
if ($pstart != -1) {
    $pstart+=2; 
    print "# FileEnd: $pstart\n";
}

my $pstart = index($bindata, "http");
if ($pstart != -1) {
    print "# URL Start: $pstart\n";
}


$x = BufferPerl($bindata);
print $x;

$x = BufferC($bindata);
my $cfile;
while(<DATA>) { $cfile .= $_; }

$cfile =~ s/::SHELLCODE::/$x/g;

open(C, ">$name.c");
print C $cfile;
close (C);

# Build PE
open  (X, ">templates/payload.bin") || die "payload.bin: $!";
print  X $bindata;
close (X);

chdir("templates") || die "chdir(templates): $!";
unlink("../$name.exe");
system("nasm -I inc/ -f bin -o ../$name.exe win32_template.asm");

# Build ELF
unlink("linux_template.o");
system("nasm -f elf -o linux_template.o linux_template.asm");
if (-f "linux_template.o")
{
    system("ld -o ../$name.elf linux_template.o");
    unlink("linux_template.o");
}

unlink("payload.bin");
system("chmod 755 *.exe *.elf");

sub BufferPerl
{
    my ($data, $width) = @_;
    my ($res, $count);

    if (! $data) { return }
    if (! $width) { $width = 16 }
    
    $res = '"';
    
    $count = 0;
    foreach my $char (split(//, $data))
    {
        if ($count == $width)
        {
            $res .= '" + ' . "\n" . '"';
            $count = 0;
        }
        $res .= sprintf("\\x%.2x", ord($char));
        $count++;
    }
    if ($count) { $res .= '"' . "\n"; }
    return $res;
}

sub BufferC
{
    my ($data, $width) = @_;
    my $res = BufferPerl($data, $width);
    if (! $res) { return }
    
    $res =~ s/\.//g;
    return $res;
}

__DATA__

char code[] =
::SHELLCODE::

int main(int argc, char **argv)
{
  int (*funct)();
  funct = (int (*)()) code;
  (int)(*funct)();
}
