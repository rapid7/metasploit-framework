require 'spec_helper'

load Metasploit::Framework.root.join('msfcli').to_path

require 'msfenv'
require 'msf/ui'
require 'msf/base'


describe Msfcli do
  subject(:msfcli) {
    described_class.new(args)
  }

  let(:args) {
    []
  }

  # Get stdout:
  # http://stackoverflow.com/questions/11349270/test-output-to-command-line-with-rspec
  def get_stdout(&block)
    out = $stdout
    $stdout = fake = StringIO.new
    begin
      yield
    ensure
      $stdout = out
    end
    fake.string
  end

  context "#initialize" do
    context 'with module name' do
      let(:args) {
        [
            module_name,
            *params
        ]
      }

      let(:module_name) {
        'multi/handler'
      }

      let(:params) {
        %w{payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1}
      }

      let(:parsed_args) {
        msfcli.instance_variable_get(:@args)
      }

      context 'multi/handler' do
        context 'with mode' do
          let(:args) {
            super() + [mode]
          }

          context 'E' do
            let(:mode) {
              'E'
            }

            it 'parses module name into :module_name arg' do
              expect(parsed_args[:module_name]).to eq(module_name)
            end

            it 'parses mode into :mode arg' do
              expect(parsed_args[:mode]).to eq(mode)
            end

            it 'parses module parameters between module name and mode' do
              expect(parsed_args[:params]).to eq(params)
            end
          end

          context 's' do
            let(:mode) {
              's'
            }

            it "parses mode as 's' (summary)" do
              expect(parsed_args[:mode]).to eq(mode)
            end
          end
        end

        context 'without mode' do
          let(:args) {
            [
                module_name
            ]
          }

          it "parses mode as 'h' (help) by default" do
            expect(parsed_args[:mode]).to eq('h')
          end
        end
      end

      context 'exploit/windows/browser/ie_cbutton_uaf' do
        let(:module_name) {
          'exploit/windows/browser/ie_cbutton_uaf'
        }

        it "strips 'exploit/' prefix for :module_name" do
          expect(parsed_args[:module_name]).to eq('windows/browser/ie_cbutton_uaf')
        end
      end

      context 'exploit/windows/browser/ie_cbutton_uaf' do
        let(:module_name) {
          'exploits/windows/browser/ie_cbutton_uaf'
        }

        it "strips 'exploits/' prefix for :module_name" do
          expect(parsed_args[:module_name]).to eq('windows/browser/ie_cbutton_uaf')
        end
      end
    end
  end

  context "#usage" do
    it "prints Usage" do
      out = get_stdout {
        msfcli.usage
      }

      expect(out).to include('Usage')
    end
  end

  #
  # This one is slow because we're loading all modules
  #
  context "#dump_module_list" do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    it 'dumps a listof modules' do
      tbl = ''

      stdout = get_stdout {
        tbl = msfcli.dump_module_list
      }

      expect(tbl).to include 'Exploits'
      expect(stdout).to include 'Please wait'
    end
  end

  context "#guess_payload_name" do
    subject(:guess_payload_name) {
      msfcli.guess_payload_name(payload_reference_name)
    }

    context 'with windows/meterpreter/reverse_tcp' do
      let(:payload_reference_name) {
        'windows/meterpreter/reverse_tcp'
      }

      it {
        is_expected.to eq(
                           [
                               /stages\/windows\/meterpreter/,
                               /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/
                           ]
                       )
      }
    end

    context 'with windows/shell/reverse_tcp' do
      let(:payload_reference_name) {
        'windows/shell/reverse_tcp'
      }

      it {
        is_expected.to eq(
                           [
                               /stages\/windows\/shell/,
                               /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/
                           ]
                       )
      }
    end

    context 'with php/meterpreter_reverse_tcp' do
      let(:payload_reference_name) {
        'php/meterpreter_reverse_tcp'
      }

      it {
        is_expected.to eq(
                              [
                                  /stages\/php\/meterpreter/,
                                  /payloads\/(stagers|stages)\/php\/.*(meterpreter_reverse_tcp)\.rb$/
                              ]
                          )
      }
    end

    context 'with linux/x86/meterpreter/reverse_tcp' do
      let(:payload_reference_name) {
        'linux/x86/meterpreter/reverse_tcp'
      }

      it {
        is_expected.to eq(
                           [
                               /stages\/linux\/x86\/meterpreter/,
                               /payloads\/(stagers|stages)\/linux\/x86\/.*(reverse_tcp)\.rb$/
                           ]
                       )
      }
    end

    context 'with java/meterpreter/reverse_tcp' do
      let(:payload_reference_name) {
        'java/meterpreter/reverse_tcp'
      }

      it {
        is_expected.to eq(
                           [
                               /stages\/java\/meterpreter/,
                               /payloads\/(stagers|stages)\/java\/.*(reverse_tcp)\.rb$/
                           ]
                       )
      }
    end

    context 'with cmd/unix/reverse' do
      let(:payload_reference_name) {
        'cmd/unix/reverse'
      }

      it {
        is_expected.to eq(
                           [
                               /stages\/cmd\/shell/,
                               /payloads\/(singles|stagers|stages)\/cmd\/.*(reverse)\.rb$/
                           ]
                       )
      }
    end

    context 'with bsd/x86/shell_reverse_tcp' do
      let(:payload_reference_name) {
        'bsd/x86/shell_reverse_tcp'
      }

      it {
        is_expected.to eq(
                           [
                               /stages\/bsd\/x86\/shell/,
                               /payloads\/(singles|stagers|stages)\/bsd\/x86\/.*(shell_reverse_tcp)\.rb$/
                           ]
                       )
      }

    end
  end

  context "#guess_encoder_name" do
    subject(:guess_encoder_name) {
      msfcli.guess_encoder_name(encoder_reference_name)
    }

    context 'with x86/shikata_ga_nai' do
      let(:encoder_reference_name) {
        'x86/shikata_ga_nai'
      }

      it {
        is_expected.to eq(
                           [/encoders\/#{encoder_reference_name}/]
                       )
      }
    end
  end
  
  
  context "#guess_nop_name" do
    subject(:guess_nop_name) {
      msfcli.guess_nop_name(nop_reference_name)
    }

    context 'with x86/shikata_ga_nai' do
      let(:nop_reference_name) {
        'x86/single_byte'
      }

      it {
        is_expected.to eq(
                           [/nops\/#{nop_reference_name}/]
                       )
      }
    end
  end

  context "#generate_whitelist" do
    subject(:generate_whitelist) {
      msfcli.generate_whitelist.map(&:to_s)
    }

    let(:args) {
      [
          'multi/handler',
          "payload=#{payload_reference_name}",
          'lhost=127.0.0.1',
          mode
      ]
    }

    let(:mode) {
      'E'
    }

    context 'with payload' do
      context 'linux/x86/reverse_tcp' do
        let(:payload_reference_name) {
          'linux/x86/reverse_tcp'
        }

        context 'with encoder' do
          let(:args) {
            super().tap { |args|
              args.insert(-2, "encoder=#{encoder_reference_name}")
            }
          }

          context 'x86/fnstenv_mov' do
            let(:encoder_reference_name) {
              'x86/fnstenv_mov'
            }

            it {
              is_expected.to match_array(
                                 [
                                     /multi\/handler/,
                                     /stages\/linux\/x86\/shell/,
                                     /payloads\/(singles|stagers|stages)\/linux\/x86\/.*(reverse_tcp)\.rb$/,
                                     /encoders\/x86\/fnstenv_mov/,
                                     /post\/.+/,
                                     /encoders\/generic\/*/,
                                     /nops\/.+/
                                 ].map(&:to_s)
                             )
            }
          end
        end
      end

      context 'windows/meterpreter/reverse_tcp' do
        let(:payload_reference_name) {
          'windows/meterpreter/reverse_tcp'
        }

        context 'with default options' do
          it {
            is_expected.to match_array(
                               [
                                   /multi\/handler/,
                                   /stages\/windows\/meterpreter/,
                                   /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/,
                                   /post\/.+/,
                                   /encoders\/generic\/*/,
                                   /encoders\/.+/,
                                   /nops\/.+/
                               ].map(&:to_s)
                           )
          }
        end

        context 'with encoder' do
          let(:args) {
            super().tap { |args|
              args.insert(-2, "encoder=#{encoder_reference_name}")
            }
          }

          context "''" do
            let(:encoder_reference_name) do
              "''"
            end

            context 'with post' do
              let(:args) {
                super().tap { |args|
                  args.insert(-2, "post=#{post_reference_name}")
                }
              }

              context "''" do
                let(:post_reference_name) do
                  "''"
                end

                context "with nop" do
                  let(:args) {
                    super().tap { |args|
                      args.insert(-2, "nop=#{nop_reference_name}")
                    }
                  }

                  context "''" do
                    let(:nop_reference_name) {
                      "''"
                    }

                    it {
                      is_expected.to match_array(
                                         [
                                             /multi\/handler/,
                                             /stages\/windows\/meterpreter/,
                                             /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/,
                                             /encoders\/''/,
                                             /post\/''/,
                                             /nops\/''/,
                                             /encoders\/generic\/*/
                                         ].map(&:to_s)
                                     )
                    }
                  end
                end
              end
            end
          end

          context "<blank>" do
            let(:encoder_reference_name) do
              ""
            end

            context 'with post' do
              let(:args) {
                super().tap { |args|
                  args.insert(-2, "post=#{post_reference_name}")
                }
              }

              context "<blank>" do
                let(:post_reference_name) do
                  ""
                end

                context "with nop" do
                  let(:args) {
                    super().tap { |args|
                      args.insert(-2, "nop=#{nop_reference_name}")
                    }
                  }

                  context "<blank>" do
                    let(:nop_reference_name) {
                      ""
                    }

                    it {
                      is_expected.to match_array(
                                         [
                                             /multi\/handler/,
                                             /stages\/windows\/meterpreter/,
                                             /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/,
                                             /encoders\/generic\/*/
                                         ].map(&:to_s)
                                     )
                    }
                  end
                end
              end
            end
          end
        end
      end
    end
  end

  context "#init_modules" do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    let(:args) {
      [
          module_name,
          mode
      ]
    }

    let(:mode) {
      'S'
    }

    context 'with exploit/windows/smb/psexec' do
      let(:module_name) {
        'exploit/windows/smb/psexec'
      }

      it 'creates the module in :module' do
        modules = {}

        Kernel.quietly {
          modules = msfcli.init_modules
        }

        expect(modules[:module]).to be_an Msf::Exploit
        expect(modules[:module].fullname).to eq(module_name)
      end
    end

    context 'with auxiliary/server/browser_autopwn' do
      let(:module_name) {
        'auxiliary/server/browser_autopwn'
      }

      it 'creates the module in :module' do
        modules = {}

        Kernel.quietly {
          modules = msfcli.init_modules
        }

        expect(modules[:module]).to be_an Msf::Auxiliary
        expect(modules[:module].fullname).to eq(module_name)
      end
    end

    context 'with post/windows/gather/credentials/gpp' do
      let(:module_name) {
        'post/windows/gather/credentials/gpp'
      }

      it 'creates the module in :module' do
        modules = {}

        Kernel.quietly {
          modules = msfcli.init_modules
        }

        expect(modules[:module]).to be_an Msf::Post
        expect(modules[:module].fullname).to eq(module_name)
      end
    end
    
    context 'with multi/handler' do
      let(:module_name) {
        'multi/handler'
      }

      it 'creates the module in :module' do
        modules = {}

        Kernel.quietly {
          modules = msfcli.init_modules
        }

        expect(modules[:module]).to be_an Msf::Exploit
        expect(modules[:module].refname).to eq(module_name)
      end
      
      context 'with payload' do
        let(:args) {
          super().tap { |args|
            args.insert(-2, "payload=#{payload_reference_name}")
          }
        }
        
        context 'windows/meterpreter/reverse_tcp' do
          let(:payload_reference_name) do
            'windows/meterpreter/reverse_tcp'
          end

          it 'creates payload in :payload' do
            modules = {}

            Kernel.quietly {
              modules = msfcli.init_modules
            }

            expect(modules[:payload]).to be_an Msf::Payload
            expect(modules[:payload].refname).to eq(payload_reference_name)
          end
        end
      end

      context 'with data store options' do
        let(:args) {
          super().tap { |args|
            args.insert(-2, "#{data_store_key}=#{data_store_value}")
          }
        }

        let(:data_store_key) {
          'lhost'
        }

        let(:data_store_value) {
          '127.0.0.1'
        }

        it 'sets data store on :module' do
          modules = {}

          Kernel.quietly {
            modules = msfcli.init_modules
          }

          expect(modules[:module].datastore[data_store_key]).to eq(data_store_value)
        end
      end
    end

    context 'with invalid module name' do
      let(:module_name) {
        'invalid/module/name'
      }

      it 'returns empty modules Hash' do
        modules = nil

        Kernel.quietly {
          modules = msfcli.init_modules
        }

        expect(modules).to eq({})
      end
    end
  end

  context "#engage_mode" do
    include_context 'Metasploit::Framework::Spec::Constants cleaner'

    it "should show me the summary of module auxiliary/scanner/http/http_version" do
      args = 'auxiliary/scanner/http/http_version s'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }

      stdout.should =~ /Module: auxiliary\/scanner\/http\/http_version/
    end

    it "should show me the options of module auxiliary/scanner/http/http_version" do
      args = 'auxiliary/scanner/http/http_version O'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }

      stdout.should =~ /The target address range or CIDR identifier/
    end

    it "should me the advanced options of module auxiliary/scanner/http/http_version" do
      args = 'auxiliary/scanner/http/http_version A'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }

      stdout.should =~ /UserAgent/
    end

    it "should show me the IDS options of module auxiliary/scanner/http/http_version" do
      args = 'auxiliary/scanner/http/http_version I'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /Insert fake relative directories into the uri/
    end

    it "should show me the targets available for module windows/browser/ie_cbutton_uaf" do
      args = "windows/browser/ie_cbutton_uaf T"
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /IE 8 on Windows 7/
    end

    it "should show me the payloads available for module windows/browser/ie_cbutton_uaf" do
      args = "windows/browser/ie_cbutton_uaf P"
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /windows\/meterpreter\/reverse_tcp/
    end

    it "should try to run the check function of an exploit" do
      args = "windows/smb/ms08_067_netapi rhost=0.0.0.1 C"  # Some BS IP so we can fail
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /#{Msf::Exploit::CheckCode::Unknown[1]}/
    end

    it "should warn my auxiliary module isn't supported by mode 'p' (show payloads)" do
      args = 'auxiliary/scanner/http/http_version p'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /This type of module does not support payloads/
    end

    it "should warn my auxiliary module isn't supported by mode 't' (show targets)" do
      args = 'auxiliary/scanner/http/http_version t'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /This type of module does not support targets/
    end

    it "should warn my exploit module isn't supported by mode 'ac' (show actions)" do
      args = 'windows/browser/ie_cbutton_uaf ac'
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /This type of module does not support actions/
    end

    it "should show actions available for module auxiliary/scanner/http/http_put" do
      args = "auxiliary/scanner/http/http_put ac"
      stdout = get_stdout {
        cli = Msfcli.new(args.split(' '))
        m = cli.init_modules
        cli.engage_mode(m)
      }
      stdout.should =~ /DELETE/
    end

  end

end
