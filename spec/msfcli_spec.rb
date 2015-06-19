require 'spec_helper'

load Metasploit::Framework.root.join('msfcli').to_path

require 'msfenv'
require 'msf/ui'
require 'msf/base'


describe Msfcli, :content do
  subject(:msfcli) {
    described_class.new(args)
  }

  #
  # methods
  #

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

  #
  # lets
  #

  let(:args) {
    []
  }

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

    let(:framework) {
      msfcli.framework
    }

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

    let(:framework) {
      msfcli.framework
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

    context 'with exploit/multi/handler' do
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

    subject(:engage_mode) {
      msfcli.engage_mode(modules)
    }

    let(:args) {
      [
          module_name,
          mode
      ]
    }

    let(:framework) {
      msfcli.framework
    }

    let(:modules) {
      msfcli.init_modules
    }

    context 'with auxiliary/scanner/http/http_put' do
      let(:module_name) {
        'auxiliary/scanner/http/http_put'
      }

      context 'with mode' do
        context 'ac' do
          let(:mode) {
            'ac'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/DELETE/)
          }
        end
      end
    end

    context 'with auxiliary/scanner/http/http_version' do
      let(:module_name) {
        'auxiliary/scanner/http/http_version'
      }

      context 'with mode' do
        context 'A' do
          let(:mode) {
            'A'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/UserAgent/)
          }
        end

        context 'I' do
          let(:mode) {
            'I'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/Insert fake relative directories into the uri/)
          }
        end

        context 'O' do
          let(:mode) {
            'O'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/The target address range or CIDR identifier/)
          }
        end

        context 'P' do
          let(:mode) {
            'P'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/This type of module does not support payloads/)
          }
        end

        context 's' do
          let(:mode) {
            's'
          }

          specify {
            expect(get_stdout { engage_mode }).to match %r{Module: auxiliary/scanner/http/http_version}
          }
        end

        context 't' do
          let(:mode) {
            't'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/This type of module does not support targets/)
          }
        end
      end
    end

    context 'with windows/browser/ie_cbutton_uaf' do
      let(:module_name) {
        'windows/browser/ie_cbutton_uaf'
      }

      context 'with mode' do
        context 'ac' do
          let(:mode) {
            'ac'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/This type of module does not support actions/)
          }
        end

        context 'P' do
          let(:mode) {
            'P'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/windows\/meterpreter\/reverse_tcp/)
          }
        end

        context 'T' do
          let(:mode) {
            'T'
          }

          specify {
            expect(get_stdout { engage_mode }).to match(/IE 8 on Windows 7/)
          }
        end
      end
    end

    context 'with windows/smb/ms08_067_netapi' do
      let(:args) {
        super().tap { |args|
          args.insert(-2, "RHOST=127.0.0.1")
        }
      }

      let(:module_name) {
        'windows/smb/ms08_067_netapi'
      }

      context 'with mode C' do
        let(:mode) {
          'C'
        }

        specify {
          expect(get_stdout { engage_mode }).to match(/#{Msf::Exploit::CheckCode::Unknown[1]}/)
        }
      end
    end
  end
end
