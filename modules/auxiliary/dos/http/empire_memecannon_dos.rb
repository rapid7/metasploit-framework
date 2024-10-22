class MetasploitModule < Msf::Modules::Exploit__Linux__Http__Empire_skywalker::MetasploitModule
	x = Msf::Modules::Exploit__Linux__Http__Empire_skywalker::MetasploitModule

	 def initialize(info = {})
	    super(
	      update_info(
	        info,
	        'Name' => 'PowerShellEmpire Meme Cannon  DoS (Skywalker)',
	        'Description' => %q{
	        	Empire C2 < 5.9.3

	        	server.py and config.yml in empire/server/. does overwriting these even crash the server

	        },
	        'Author' => [
	        # building on linux/http/empire_skywalker.rb
	          'ACE-Responder',    # Patch bypass discovery & Python PoC
	          'Takahiro Yokoyama', # Update Metasploit module
	          'gardnerapp' # Meme cannon
	        ],
	        'License' => MSF_LICENSE,
	        'References' => [
	          ['CVE', '2024-6127'], # patch bypass
	          ['URL', 'https://aceresponder.com/blog/exploiting-empire-c2-framework'], # patch bypass
	          ['URL', 'https://github.com/ACE-Responder/Empire-C2-RCE-PoC/tree/main'] # patch bypass
	        ],
	        'DisclosureDate' => '2016-10-15',
	        'Notes' => {
	          'Stability' => [ CRASH_SAFE, ],
	          'SideEffects' => [ ARTIFACTS_ON_DISK, ]
	        }
	      )
	    )

	    register_options(
	      [
	        Opt::RPORT(8080),
	        # original
	        OptString.new('TARGETURI', [ false, 'Base URI path', '/' ]),
	        OptString.new('STAGE0_URI', [ true, 'The resource requested by the initial launcher, default is index.asp', 'index.asp' ]),
	        OptString.new('STAGE1_URI', [ true, 'The resource used by the RSA key post, default is index.jsp', 'index.jsp' ]),
	        OptString.new('PROFILE', [ false, 'Empire agent traffic profile URI.', '' ]),
	        # patch bypass
	        OptEnum.new('CVE', [true, 'The vulnerability to use', 'CVE-2024-6127', ['CVE-2024-6127', 'Original']]),
	        OptString.new('STAGE_PATH', [ true, 'The Empire\'s staging path, default is login/process.php', 'login/process.php' ]),
	        OptString.new('AGENT', [ true, 'The Empire\'s communication profile agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'])
	      ]
	    )
	end 

	def exploit
	end 

	# class self << Msf::Modules::Exploit__Linux__Http__Empire_skywalker::MetasploitModule ??
	# super out what you don't need 

	# Meme Storage
	class Meme
		
		memes = {
			:doge => "",

			:nyan => "",

			:pepe => "",
		}

		memes.each_pair do |k, v|
			define_method "self.#{k}" do
				eval("@#{k} = base64.decode #{v}", __FILE__,__LINE__,get_binding)
			end 
		end 

	end 

end