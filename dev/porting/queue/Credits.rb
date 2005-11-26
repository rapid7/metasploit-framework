require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Metasploit Framework Credits',
			'Description'    => %q{
				This module will display a list of the Metasploit developers
				and contributors. If you have submitted something to the
				project and do not see your name or handle here, please drop
				us an email.
					
			},
			'Author'         => [ 'The Metasploit Development Team' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://www.metasploit.com'],

				],
			'Privileged'     => false,
			
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'any',
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

package Msf::Exploit::Credits;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use FindBin qw{$RealScript};

my $advanced = {
  'SleepLength' => [4, 'Length to sleep between people'],
};

my $info = {
  'Name'    => 'Metasploit Framework Credits',
  'Version'  => '$Revision$',
  'Authors' => [ 'The Metasploit Development Team', ],
  'Arch'    => [  ],
  'OS'      => [  ],
  'Priv'    => 0,
  'UserOpts'  =>
    {
    },
  'Description'  => Pex::Text::Freeform(qq{
	This module will display a list of the Metasploit developers and 
	contributors. If you have submitted something to the project and
	do not see your name or handle here, please drop us an email.
    }),
  'Refs'  =>
    [
      'http://www.metasploit.com',
    ],
  'Keys' => ['credits'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

  return($self);
}

sub Exploit {
  my $self = shift;

#  my $target = $self->Targets->[$targetIndex];

  my $sleep = $self->GetLocal('SleepLength');

  $self->PrintFrame;
  sleep(1);
  $self->PrintClear;

  $self->PrintHD;
  sleep($sleep);
  $self->PrintClear;
  
  $self->PrintSpoonm;
  sleep($sleep);
  $self->PrintClear;
  
  $self->PrintClear;
  $self->PrintSkape;
  sleep($sleep);
  
  $self->PrintClear;
  $self->PrintOptyx;
  sleep($sleep);
  
  $self->PrintClear;
  $self->PrintVlad;
  sleep($sleep);
  
  $self->PrintClear; 
  
  
  $self->PrintGeneralContrib;
  sleep(1);
  $self->PrintGeneralNames;
  sleep(5);
  
}

sub PrintClear {
  my $self = shift;
  $self->PrintLine("\n" x 4);
}

sub PrintFrame {
  my $self = shift;

  my $frame = q{
  #########################################

         Framework Development Team

  #########################################


};

  $self->PrintLine($frame);
}

sub PrintMainContrib {
  my $self = shift;

  my $frame = q{
  #########################################

     Repeat Offenders (Main Contributors)

  #########################################


};

  $self->PrintLine($frame);
}

sub PrintGeneralContrib {
  my $self = shift;

  my $frame = q{
  #########################################

            General Contributors

  #########################################


};

  $self->PrintLine($frame);
}


sub PrintGeneralNames {
	my $self = shift;
	my $names = q@

Exploit Contributors:

    + trew + bmc + marco + jcyberpnk + stinko 
    + one-two + optyx + skape + spoonm + TD
    + juliano + hdm + arrigo + 0dd + grutz
    + sam_ + noir + thor + vlad902 + ghandi
    + acaro + cybertronic + solar eclipse
    + et lownoise + thief + MC


Payload Contributors:

    + bighawk + skape + optyx + vlad902
    + lsd + spoonm + gera + acuttergo 
    + ghandi + jarrko + hdm 


Encoder Contributors:
    
    + juliano + ghandi + spoonm + optyx
    + skylined + hdm + skape + vlad902


Nop Contributors:

    + k2 + spoonm + optyx + hdm + vlad902
 

Feedback & Testing:

    + msf beta team + arrigo + marco + stinko
    + slow + ddi + 0dd + lupin2000 + MC
    + valsmith + framework-list


Graphics & Logos:

    + jbl + riotz + cowsay + figlet


@;

	$self->PrintLine($names);
}



sub PrintHD {
  my $self = shift;

  my $hd = q@
     .--""--.    
   .'        '.      Name: HD Moore
  /   .'``'.   \   Skills: 31337
 |  .'/.\/.\'.  |   Quote: "Sure, that will take 5 minutes..."
 |  : |_/\_| ;  |  
  \ '.\    /.' /   Reponsible For:
  /'. `'--'` .'\     Metasploit Project
 /_  `-./\.-'  _\'   Metasploit Framework
)_/  I'm With  \_)   Win32 Payloads and Exploits
      0day ->        Encoders, SMB, Tab Completion
  '------------'`


@;

  $self->PrintLine($hd);
}

sub PrintSpoonm {
  my $self = shift;
  my $spoon = 
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2e\x2d".
    "\x2d\x2d\x2d\x2d\x2e\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20".
    "\x20\x20\x2c\x27\x20\x2d\x20\x20\x20\x2d\x20\x60\x2e\x0a\x20\x20".
    "\x20\x20\x5f\x20\x5f\x5f\x5f\x5f\x5f\x2f\x20\x20\x3c\x71\x3e\x20".
    "\x3c\x70\x3e\x20\x20\x5c\x5f\x5f\x5f\x5f\x5f\x20\x5f\x0a\x20\x20".
    "\x20\x2f\x5f\x7c\x7c\x20\x20\x20\x7c\x7c\x60\x2d\x2e\x5f\x5f\x5f".
    "\x5f\x5f\x2e\x2d\x60\x7c\x7c\x20\x20\x20\x7c\x7c\x2d\x5c\x20\x20".
    "\x20\x20\x4e\x61\x6d\x65\x3a\x20\x73\x70\x6f\x6f\x6e\x6d\x0a\x20".
    "\x20\x2f\x20\x5f\x7c\x7c\x3d\x3d\x3d\x7c\x7c\x20\x20\x20\x20\x20".
    "\x20\x20\x20\x20\x20\x20\x7c\x7c\x3d\x3d\x3d\x7c\x7c\x20\x5f\x5c".
    "\x20\x53\x6b\x69\x6c\x6c\x73\x3a\x20\x4f\x4f\x50\x65\x72\x6c\x20".
    "\x61\x6e\x64\x20\x41\x73\x6d\x20\x43\x6f\x77\x62\x6f\x79\x0a\x20".
    "\x7c\x2d\x20\x5f\x7c\x7c\x3d\x3d\x3d\x7c\x7c\x3d\x3d\x3d\x3d\x3d".
    "\x3d\x3d\x3d\x3d\x3d\x3d\x7c\x7c\x3d\x3d\x3d\x7c\x7c\x2d\x20\x5f".
    "\x7c\x20\x51\x75\x6f\x74\x65\x3a\x20\x22\x22\x0a\x20\x5c\x5f\x5f".
    "\x5f\x7c\x7c\x5f\x5f\x5f\x7c\x7c\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f".
    "\x5f\x5f\x5f\x7c\x7c\x5f\x5f\x5f\x7c\x7c\x5f\x5f\x5f\x2f\x0a\x20".
    "\x20\x5c\x5c\x7c\x2f\x2f\x2f\x20\x20\x20\x5c\x5f\x3a\x5f\x3a\x5f".
    "\x3a\x5f\x3a\x5f\x3a\x5f\x2f\x20\x20\x20\x5c\x5c\x5c\x7c\x2f\x2f".
    "\x20\x52\x65\x73\x70\x6f\x6e\x73\x69\x62\x6c\x65\x20\x46\x6f\x72".
    "\x3a\x0a\x20\x20\x7c\x20\x20\x20\x5f\x7c\x20\x20\x20\x20\x7c\x5f".
    "\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x7c\x20\x20\x20\x20\x7c\x20\x20".
    "\x20\x5f\x7c\x20\x20\x20\x4d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74".
    "\x20\x46\x72\x61\x6d\x65\x77\x6f\x72\x6b\x0a\x20\x20\x7c\x20\x20".
    "\x20\x5f\x7c\x20\x20\x20\x2f\x28\x20\x3d\x3d\x3d\x3d\x3d\x3d\x3d".
    "\x20\x29\x5c\x20\x20\x20\x7c\x20\x20\x20\x5f\x7c\x20\x20\x20\x42".
    "\x72\x61\x69\x6e\x62\x75\x73\x74\x69\x6e\x67\x20\x44\x79\x6e\x61".
    "\x6d\x69\x63\x20\x4f\x4f\x0a\x20\x20\x5c\x5c\x7c\x7c\x2f\x2f\x20".
    "\x20\x2f\x5c\x20\x60\x2d\x2e\x5f\x5f\x5f\x2e\x2d\x27\x20\x2f\x5c".
    "\x20\x20\x5c\x5c\x7c\x7c\x2f\x2f\x20\x20\x20\x45\x78\x70\x6c\x6f".
    "\x69\x74\x73\x20\x61\x6e\x64\x20\x50\x61\x79\x6c\x6f\x61\x64\x73".
    "\x0a\x20\x20\x20\x28\x6f\x20\x29\x20\x20\x2f\x5f\x20\x27\x2e\x5f".
    "\x5f\x5f\x5f\x5f\x5f\x5f\x2e\x27\x20\x5f\x5c\x20\x20\x28\x20\x6f".
    "\x29\x20\x20\x20\x20\x53\x6f\x63\x6b\x65\x74\x20\x4e\x69\x6e\x6a".
    "\x69\x74\x73\x75\x0a\x20\x20\x2f\x5f\x5f\x2f\x20\x5c\x20\x7c\x20".
    "\x20\x20\x20\x5f\x7c\x20\x20\x20\x7c\x5f\x20\x20\x20\x5f\x7c\x20".
    "\x2f\x20\x5c\x5f\x5f\x5c\x0a\x20\x20\x2f\x2f\x2f\x5c\x5f\x2f\x20".
    "\x7c\x5f\x20\x20\x20\x5f\x7c\x20\x20\x20\x7c\x20\x20\x20\x20\x5f".
    "\x7c\x20\x5c\x5f\x2f\x5c\x5c\x5c\x0a\x20\x2f\x2f\x2f\x5c\x5c\x5f".
    "\x5c\x20\x5c\x20\x20\x20\x20\x5f\x2f\x20\x20\x20\x5c\x20\x20\x20".
    "\x20\x5f\x2f\x20\x2f\x5f\x2f\x2f\x5c\x5c\x5c\x0a\x20\x5c\x5c\x7c".
    "\x2f\x2f\x5f\x2f\x20\x2f\x2f\x2f\x7c\x5c\x5c\x5c\x20\x20\x20\x2f".
    "\x2f\x2f\x7c\x5c\x5c\x5c\x20\x5c\x5f\x5c\x5c\x7c\x2f\x2f\x0a\x20".
    "\x20\x20\x20\x20\x20\x20\x20\x20\x5c\x5c\x5c\x7c\x2f\x2f\x2f\x20".
    "\x20\x20\x5c\x5c\x5c\x7c\x2f\x2f\x2f\x0a\x20\x20\x20\x20\x20\x20".
    "\x20\x20\x20\x2f\x2d\x20\x20\x5f\x5c\x5c\x20\x20\x20\x2f\x2f\x20".
    "\x20\x20\x5f\x5c\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x7c\x20".
    "\x20\x20\x5f\x7c\x7c\x20\x20\x20\x7c\x7c\x2d\x20\x20\x5f\x7c\x0a".
    "\x20\x20\x20\x20\x20\x20\x20\x2c\x2f\x5c\x5f\x5f\x5f\x5f\x7c\x7c".
    "\x20\x20\x20\x7c\x7c\x20\x5f\x5f\x5f\x2f\x5c\x2c\x0a\x20\x20\x20".
    "\x20\x20\x20\x2f\x7c\x5c\x5f\x5f\x5f\x60\x5c\x2c\x7c\x20\x20\x20".
    "\x7c\x2c\x2f\x27\x5f\x5f\x5f\x2f\x7c\x5c\x0a\x20\x20\x20\x20\x20".
    "\x20\x7c\x7c\x7c\x60\x2e\x5c\x5c\x20\x5c\x5c\x20\x20\x20\x2f\x2f".
    "\x20\x2f\x2f\x2c\x27\x7c\x7c\x7c\x0a\x20\x20\x20\x20\x20\x20\x5c".
    "\x5c\x5c\x5c\x5f\x2f\x2f\x5f\x2f\x2f\x20\x20\x20\x5c\x5c\x5f\x5c".
    "\x5c\x5f\x2f\x2f\x2f\x2f\x20\x4c\x47\x42\x2f\x66\x73\x63";

  $self->PrintLine($spoon);
  return;
}


sub PrintSkape {
  my $self = shift;

  my $skape = q{
    __________               
  ."          ".  
  | .--------. |     Name: Skape
 /` |________| `\  Skills: Win32 and x86 Asm Ninja 
|  / / .\/. \ \  |  Quote: "Skape rewrote my shellcode in half the size, again"
\_/  \__/\__/  \_/ 
  \            /   Reponsible For:
  /'._  --  _.'\     Windows/Linux Library Injection
 /_   `""""`   _\    Small Payloads
 )_|   hick    |_)   BSDI Exploits and Payloads
   \__________/|;    Meterpreter
   '----------'      Opcode Database  

};

  $self->PrintLine($skape);
}

sub PrintOptyx {
  my $self = shift;

  my $optyx = q@
            _            _.,----,                                    
 __  _.-._ / '-.        -  ,._  \)      
|  `-)_   '-.   \       / < _ )/" } 
/___   '-.   \   '-, ___(c-(6)=(6)
 ,  '.    -._ '.  _,'   >\    "  ) 
 :;;,,'-._   '---' (  ( "/`. -='/ 
;:;;:;;,   \._     .`-.)Y'- '--'    Name: Optyx
;';:;;;;;'-._ /'._|   |//  _/' \  Skills: One of the Ancients
      '''"._ F    |  _/ _.'._   `\ Quote: "So I found this bug in gravity..."
             L    \   \/     '._  \ 
      .-,-,_ |     `.  `'---,  \_ _|    
      //    '|    /  \,   ("--',=`)7    
     | `._       : _,  \  /'`-._\,_'-._ 
     '--' '-.\__/ _L   .`'         '.// 
                 [ (  /    Responsible For:             
                  ) `{       Encoders, Exploits, Payloads             
       snd        \__)       Sparc, PPC, Mips Eliteness
@;

  $self->PrintLine($optyx);
}

sub PrintVlad {
  my $self = shift;

  my $vlad902 = q@
          __________
          |        |
          |________|
           |      |
        .-'        '-.
     .-'    .---.     '-.
  .-'     .'.--. '.      '-.
 /        ' /~`') '         \
|         '.`, ( .'          |   Name: Vlad902
|           '---'            | Skills: Many
|     .           .      .   |  Quote: "God I love this e250"
| ,-. |-. ,-. ,-. |  . . |-  |
| ,-| | | `-. | | |  | | |   | Responsible For:
| `-^ ^-' `-' `-' `' `-^ `'  |   BSD Exploits and Payloads
|                            |   Sparc and Alpha Kung Foo
,.   , ,,--. .,--. ,, ,    ,.|   SunRPC and XDR codeage
||  /  |   |  |   \ |/    / || 
|| /   |   |  |   / |\   /~~||
|`'    `---' `^--' ,' `,'   `|
|                            |
|                            |
|                            |
|                            | ML  
 \__________________________/

@;

  $self->PrintLine($vlad902);
}
1;

=end


end
end	
