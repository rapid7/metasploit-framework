# -*- coding:binary -*-
require 'spec_helper'
require 'msf/core'

def decompress(code)
  Rex::Powershell::Script.new(code).decompress_code
end

describe Rex::Powershell::Command do
  let(:example_script) do
    File.join(Msf::Config.data_directory, "exploits", "powershell", "powerdump.ps1")
  end

  let(:payload) do
    Rex::Text.rand_text_alpha(120)
  end

  let(:arch) do
    'x86'
  end

  describe "::encode_script" do
    it 'should read and encode a sample script file' do
      script = subject.encode_script(example_script)
      script.should be
      script.length.should be > 0
    end
  end

  describe "::compress_script" do
    context 'with default options' do
      it 'should create a compressed script' do
        script = File.read(example_script)
        compressed = subject.compress_script(script)
        compressed.length.should be < script.length
        compressed.include?('IO.Compression').should be_truthy
      end

      it 'should create a compressed script with eof' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, 'end_of_file')
        compressed.include?('end_of_file').should be_truthy
      end
    end

    context 'when strip_comments is true' do
      it 'should strip comments' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: true)
        compressed.length.should be < script.length
      end
    end
    context 'when strip_comment is false' do
      it 'shouldnt strip comments' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: false)
        compressed.length.should be < script.length
      end
    end

    context 'when strip_whitespace is true' do
      it 'should strip whitespace' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: false, strip_whitespace: true)
        decompress(compressed).length.should be < script.length
      end
    end

    context 'when strip_whitespace is false' do
      it 'shouldnt strip whitespace' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: false, strip_whitespace: false)
        expect(decompress(compressed).length).to eq(script.length)
      end
    end

    context 'when sub_vars is true' do
      it 'should substitute variables' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_vars: true)
        decompress(compressed).include?('$hashes').should be_falsey
      end
    end

    context 'when sub_vars is false' do
      it 'shouldnt substitute variables' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_vars: false)
        decompress(compressed).include?('$hashes').should be_truthy
      end
    end

    context 'when sub_funcs is true' do
      it 'should substitute functions' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_funcs: true)
        decompress(compressed).include?('DumpHashes').should be_falsey
      end
    end

    context 'when sub_funcs is false' do
      it 'shouldnt substitute variables' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_funcs: false)
        decompress(compressed).include?('DumpHashes').should be_truthy
      end
    end
  end

  describe "::run_hidden_psh" do
    let(:encoded) do
      false
    end

    context 'when x86 payload' do
      it 'should generate code' do
        code = subject.run_hidden_psh(payload, arch, encoded)
        code.include?('syswow64').should be_truthy
      end
    end

    context 'when x64 payload' do
      it 'should generate code'  do
        code = subject.run_hidden_psh(payload, 'x86_64', encoded)
        code.include?('sysnative').should be_truthy
      end
    end

    context 'when encoded' do
      it 'should generate a code including an encoded command' do
        code = subject.run_hidden_psh(payload, arch, true)
        code.include?('-nop -w hidden -e ').should be_truthy
      end
    end

    context 'when command' do
      it 'should generate code including a -c command' do
        code = subject.run_hidden_psh(payload, arch, encoded)
        code.include?('-nop -w hidden -c ').should be_truthy
      end
    end

    context 'when old' do
      it 'should generate a code including unshorted args' do
        code = subject.run_hidden_psh(payload, arch, encoded, method: 'old')
        code.include?('-NoProfile -WindowStyle hidden -NoExit -Command ').should be_truthy
      end
    end
  end

  describe "::cmd_psh_payload" do
    let(:template_path) do
      File.join(Msf::Config.data_directory,
                "templates",
                "scripts")
    end

    let(:psh_method) do
      'reflection'
    end

    context 'when payload is huge' do
      it 'should raise an exception' do
        except = false
        begin
          code = subject.cmd_psh_payload(Rex::Text.rand_text_alpha(12000), arch, template_path, method: psh_method)
        rescue RuntimeError => e
          except = true
        end

        except.should be_truthy
      end
    end

    context 'when persist is true' do
      it 'should add a persistance loop' do
        code = subject.cmd_psh_payload(payload, arch, template_path, persist: true, method: psh_method)
        decompress(code).include?('while(1){Start-Sleep -s ').should be_truthy
      end
    end

    context 'when persist is false' do
      it 'shouldnt add a persistance loop' do
        code = subject.cmd_psh_payload(payload, arch, template_path, persist: false, method: psh_method)
        decompress(code).include?('while(1){Start-Sleep -s ').should be_falsey
      end
    end

    context 'when prepend_sleep is set' do
      it 'should prepend sleep' do
        code = subject.cmd_psh_payload(payload, arch, template_path, prepend_sleep: 5, method: psh_method)
        decompress(code).include?('Start-Sleep -s ').should be_truthy
      end
    end

    context 'when prepend_sleep isnt set' do
      it 'shouldnt prepend sleep' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: psh_method)
        decompress(code).include?('Start-Sleep -s ').should be_falsey
      end
    end

    context 'when prepend_sleep is 0' do
      it 'shouldnt prepend sleep' do
        code = subject.cmd_psh_payload(payload, arch, template_path, prepend_sleep: 0, method: psh_method)
        decompress(code).include?('Start-Sleep -s ').should be_falsey
      end
    end

    context 'when method is old' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'old')
        decompress(code).include?('-namespace Win32Functions').should be_truthy
      end
      it 'shouldnt shorten args' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'old')
        code.include?('-NoProfile -WindowStyle hidden -Command').should be_truthy
      end
      it 'should include -NoExit' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'old')
        code.include?('-NoProfile -WindowStyle hidden -NoExit -Command').should be_truthy
      end
    end

    context 'when method is net' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'net')
        decompress(code).include?('System.Runtime.InteropServices;').should be_truthy
      end
    end

    context 'when method is reflection' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'reflection')
        decompress(code).include?('GlobalAssemblyCache').should be_truthy
      end
    end

    context 'when method is msil' do
      it 'should raise an exception' do
        except = false
        begin
          subject.cmd_psh_payload(payload, arch, template_path, method: 'msil')
        rescue RuntimeError
          except = true
        end
        except.should be_truthy
      end
    end

    context 'when method is unknown' do
      it 'should raise an exception' do
        except = false
        begin
          subject.cmd_psh_payload(payload, arch, template_path, method: 'blah')
        rescue RuntimeError
          except = true
        end
        except.should be_truthy
      end
    end

    context 'when encode_inner_payload' do
      it 'should contain an inner payload with -e' do
          code = subject.cmd_psh_payload(payload, arch, template_path, encode_inner_payload: true, method: psh_method)
          code.include?(' -e ').should be_truthy
      end

      context 'when no_equals is true' do
        it 'should raise an exception' do
          except = false
          begin
            code = subject.cmd_psh_payload(payload, arch, template_path, encode_inner_payload: true, no_equals: true, method: psh_method)
          rescue RuntimeError
            except = true
          end
          except.should be_truthy
        end
      end
    end

    context 'when encode_final_payload' do
      context 'when no_equals is false' do
        it 'should contain a final payload with -e' do
          code = subject.cmd_psh_payload(payload, arch, template_path, encode_final_payload: true, no_equals: false, method: psh_method)
          code.include?(' -e ').should be_truthy
          code.include?(' -c ').should be_falsey
        end
      end
      context 'when no_equals is true' do
        it 'should contain a final payload with -e' do
          code = subject.cmd_psh_payload(payload, arch, template_path, encode_final_payload: true, no_equals: true, method: psh_method)
          code.include?(' -e ').should be_truthy
          code.include?(' -c ').should be_falsey
          code.include?('=').should be_falsey
        end
      end
      context 'when encode_inner_payload is true' do
        it 'should raise an exception' do
          except = false
          begin
            subject.cmd_psh_payload(payload, arch, template_path, encode_final_payload: true, encode_inner_payload: true, method: psh_method)
          rescue RuntimeError
            except = true
          end
          except.should be_truthy
        end
      end
    end

    context 'when remove_comspec' do
      it 'shouldnt contain %COMSPEC%' do
        code = subject.cmd_psh_payload(payload, arch, template_path, remove_comspec: true, method: psh_method)
        code.include?('%COMSPEC%').should be_falsey
      end
    end

    context 'when use single quotes' do
      it 'should wrap in single quotes' do
        code = subject.cmd_psh_payload(payload, arch, template_path, use_single_quotes: true, method: psh_method)
        code.include?(' -c \'').should be_truthy
      end
    end
  end

  describe "::generate_psh_command_line" do
    it 'should contain no full stop when :no_full_stop' do
      opts = {:no_full_stop => true}
      command = subject.generate_psh_command_line(opts)
      command.include?("powershell ").should be_truthy
    end

    it 'should contain full stop unless :no_full_stop' do
      opts = {}
      command = subject.generate_psh_command_line(opts)
      command.include?("powershell.exe ").should be_truthy

      opts = {:no_full_stop => false}
      command = subject.generate_psh_command_line(opts)
      command.include?("powershell.exe ").should be_truthy
    end

    it 'should ensure the path should always ends with \\' do
      opts = {:path => "test"}
      command = subject.generate_psh_command_line(opts)
      command.include?("test\\powershell.exe ").should be_truthy

      opts = {:path => "test\\"}
      command = subject.generate_psh_command_line(opts)
      command.include?("test\\powershell.exe ").should be_truthy
    end
  end

  describe "::generate_psh_args" do
    it 'should return empty string for nil opts' do
      subject.generate_psh_args(nil).should eql ""
    end

    command_args = [[:encodedcommand, "parp"],
                    [:executionpolicy, "bypass"],
                    [:inputformat, "xml"],
                    [:file, "x"],
                    [:noexit, true],
                    [:nologo, true],
                    [:noninteractive, true],
                    [:mta, true],
                    [:outputformat, 'xml'],
                    [:sta, true],
                    [:noprofile, true],
                    [:windowstyle, "hidden"],
                    [:command, "Z"]
    ]

    permutations = (0..command_args.length).to_a.combination(2).map{|i,j| command_args[i...j]}

    permutations.each do |perms|
      opts = {}
      perms.each do |k,v|
        opts[k] = v
        it "should generate correct arguments for #{opts}" do
          opts[:shorten] = true
          short_args = subject.generate_psh_args(opts)
          opts[:shorten] = false
          long_args = subject.generate_psh_args(opts)

          opt_length = opts.length - 1

          short_args.should_not be_nil
          long_args.should_not be_nil
          short_args.count('-').should eql opt_length
          long_args.count('-').should eql opt_length
          short_args[0].should_not eql " "
          long_args[0].should_not eql " "
          short_args[-1].should_not eql " "
          long_args[-1].should_not eql " "

          if opts[:command]
            long_args[-10..-1].should eql "-Command Z"
            short_args[-4..-1].should eql "-c Z"
          end
       end
      end
    end
  end

end

