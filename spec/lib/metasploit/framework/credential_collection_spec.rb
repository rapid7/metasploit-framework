require 'spec_helper'
require 'metasploit/framework/credential_collection'

RSpec.describe Metasploit::Framework::CredentialCollection do

  subject(:collection) do
    described_class.new(
      nil_passwords: nil_passwords,
      blank_passwords: blank_passwords,
      pass_file: pass_file,
      password: password,
      user_as_pass: user_as_pass,
      user_file: user_file,
      username: username,
      userpass_file: userpass_file,
      prepended_creds: prepended_creds,
      additional_privates: additional_privates,
      additional_publics: additional_publics,
      password_spray: password_spray,
      ignore_public: ignore_public,
      ignore_private: ignore_private
    )
  end

  before(:each) do
    # The test suite overrides File.open(...) calls; fall back to the normal behavior for any File.open calls that aren't explicitly mocked
    allow(File).to receive(:open).with(anything).and_call_original
    allow(File).to receive(:open).with(anything, anything).and_call_original
    allow(File).to receive(:open).with(anything, anything, anything).and_call_original
  end

  let(:nil_passwords) { nil }
  let(:blank_passwords) { nil }
  let(:username) { "user" }
  let(:password) { "pass" }
  let(:user_file) { nil }
  let(:pass_file) { nil }
  let(:user_as_pass) { nil }
  let(:userpass_file) { nil }
  let(:prepended_creds) { [] }
  let(:additional_privates) { [] }
  let(:additional_publics) { [] }
  let(:password_spray) { false }
  let(:ignore_public) { nil }
  let(:ignore_private) { nil }

  describe "#each" do
    specify do
      expect { |b| collection.each(&b) }.to yield_with_args(Metasploit::Framework::Credential)
    end

    context "when given a user_file and password" do
      let(:username) { nil }
      let(:user_file) do
        filename = "foo"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename,/^r/).and_yield stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: "asdf", private: password),
          Metasploit::Framework::Credential.new(public: "jkl", private: password),
        )
      end
    end

    context "when given a pass_file and username" do
      let(:password) { nil }
      let(:pass_file) do
        filename = "foo"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename,/^r/).and_return stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: "asdf"),
          Metasploit::Framework::Credential.new(public: username, private: "jkl"),
        )
      end
    end

    context "when given a userspass_file" do
      let(:username) { nil }
      let(:password) { nil }
      let(:userpass_file) do
        filename = "foo"
        stub_file = StringIO.new("asdf jkl\nfoo bar\n")
        allow(File).to receive(:open).with(filename,/^r/).and_yield stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: "asdf", private: "jkl"),
          Metasploit::Framework::Credential.new(public: "foo", private: "bar"),
        )
      end
    end

    context "when given a pass_file and user_file" do
      let(:password) { nil }
      let(:username) { nil }
      let(:user_file) do
        filename = "user_file"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename,/^r/).and_yield stub_file

        filename
      end
      let(:pass_file) do
        filename = "pass_file"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename,/^r/).and_return stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: "asdf", private: "asdf"),
          Metasploit::Framework::Credential.new(public: "asdf", private: "jkl"),
          Metasploit::Framework::Credential.new(public: "jkl", private: "asdf"),
          Metasploit::Framework::Credential.new(public: "jkl", private: "jkl"),
        )
      end
    end

    context "when given a pass_file and user_file and password spray" do
      let(:password) { nil }
      let(:username) { nil }
      let(:password_spray) { true }
      let(:pass_file) do
        filename = "pass_file"
        stub_file = StringIO.new("password1\npassword2\n")
        allow(File).to receive(:open).with(filename,/^r/).and_yield stub_file

        filename
      end
      let(:user_file) do
        filename = "user_file"
        stub_file = StringIO.new("user1\nuser2\nuser3\n")
        allow(File).to receive(:open).with(filename,/^r/).and_return stub_file

        filename
      end

      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: "user1", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user2", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user3", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user1", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user2", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user3", private: "password2"),
        )
      end

      context 'when :user_as_pass is true' do
        let(:user_as_pass) { true }

        specify  do
          expect { |b| collection.each(&b) }.to yield_successive_args(
            Metasploit::Framework::Credential.new(public: "user1", private: "user1"),
            Metasploit::Framework::Credential.new(public: "user2", private: "user2"),
            Metasploit::Framework::Credential.new(public: "user3", private: "user3"),
            Metasploit::Framework::Credential.new(public: "user1", private: "password1"),
            Metasploit::Framework::Credential.new(public: "user2", private: "password1"),
            Metasploit::Framework::Credential.new(public: "user3", private: "password1"),
            Metasploit::Framework::Credential.new(public: "user1", private: "password2"),
            Metasploit::Framework::Credential.new(public: "user2", private: "password2"),
            Metasploit::Framework::Credential.new(public: "user3", private: "password2"),
          )
        end
      end
    end

    context 'when given a username and password' do
      let(:password) { 'password' }
      let(:username) { 'root' }

      specify do
        expected = [
          Metasploit::Framework::Credential.new(public: 'root', private: 'password'),
        ]
        expect { |b| collection.each(&b) }.to yield_successive_args(*expected)
      end
    end

    context 'when given a pass_file, user_file, password spray and a default username' do
      let(:password) { nil }
      let(:username) { 'root' }
      let(:password_spray) { true }
      let(:pass_file) do
        filename = "pass_file"
        stub_file = StringIO.new("password1\npassword2\n")
        allow(File).to receive(:open).with(filename,/^r/).and_yield stub_file

        filename
      end
      let(:user_file) do
        filename = "user_file"
        stub_file = StringIO.new("user1\nuser2\nuser3\n")
        allow(File).to receive(:open).with(filename,/^r/).and_return stub_file

        filename
      end

      specify do
        expected = [
          Metasploit::Framework::Credential.new(public: "root", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user1", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user2", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user3", private: "password1"),
          Metasploit::Framework::Credential.new(public: "root", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user1", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user2", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user3", private: "password2"),
        ]
        expect { |b| collection.each(&b) }.to yield_successive_args(*expected)
      end
    end

    context 'when given a pass_file, user_file, password spray and additional privates' do
      let(:password) { nil }
      let(:username) { 'root' }
      let(:password_spray) { true }
      let(:additional_privates) { ['foo'] }
      let(:pass_file) do
        filename = "pass_file"
        stub_file = StringIO.new("password1\npassword2\n")
        allow(File).to receive(:open).with(filename,/^r/).and_yield stub_file

        filename
      end
      let(:user_file) do
        filename = "user_file"
        stub_file = StringIO.new("user1\nuser2\nuser3\n")
        allow(File).to receive(:open).with(filename,/^r/).and_return stub_file

        filename
      end

      specify do
        expected = [
          Metasploit::Framework::Credential.new(public: "root", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user1", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user2", private: "password1"),
          Metasploit::Framework::Credential.new(public: "user3", private: "password1"),
          Metasploit::Framework::Credential.new(public: "root", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user1", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user2", private: "password2"),
          Metasploit::Framework::Credential.new(public: "user3", private: "password2"),
          Metasploit::Framework::Credential.new(public: "root", private: "foo"),
          Metasploit::Framework::Credential.new(public: "user1", private: "foo"),
          Metasploit::Framework::Credential.new(public: "user2", private: "foo"),
          Metasploit::Framework::Credential.new(public: "user3", private: "foo"),
        ]
        expect { |b| collection.each(&b) }.to yield_successive_args(*expected)
      end
    end

    context 'when given a username, user_file and pass_file' do
      let(:password) { nil }
      let(:username) { 'my_username' }
      let(:user_file) do
        filename = "user_file"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename, /^r/).and_yield stub_file

        filename
      end

      let(:pass_file) do
        filename = "pass_file"
        stub_file = StringIO.new("asdf\njkl\n")
        allow(File).to receive(:open).with(filename, /^r/).and_return stub_file

        filename
      end

      it do
        expect { |b| collection.each(&b) }.to yield_successive_args(
                                                Metasploit::Framework::Credential.new(public: "my_username", private: "asdf"),
                                                Metasploit::Framework::Credential.new(public: "my_username", private: "jkl"),
                                                Metasploit::Framework::Credential.new(public: "asdf", private: "asdf"),
                                                Metasploit::Framework::Credential.new(public: "asdf", private: "jkl"),
                                                Metasploit::Framework::Credential.new(public: "jkl", private: "asdf"),
                                                Metasploit::Framework::Credential.new(public: "jkl", private: "jkl")
                                              )
      end
    end

    context "when :user_as_pass is true" do
      let(:user_as_pass) { true }
      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: password),
          Metasploit::Framework::Credential.new(public: username, private: username),
        )
      end
    end

    context "when :nil_passwords is true" do
      let(:nil_passwords) { true }
      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: nil),
          Metasploit::Framework::Credential.new(public: username, private: password),
        )
      end
    end

    context "when :blank_passwords is true" do
      let(:blank_passwords) { true }
      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: password),
          Metasploit::Framework::Credential.new(public: username, private: ""),
        )
      end
    end

    context 'when :ignore_public is true and :username is nil' do
      let(:ignore_public) { true }
      let(:username) { nil }
      specify  do
        expect { |b| collection.each(&b) }.to_not yield_control
      end
    end

    context 'when :ignore_private is true and password is nil' do
      let(:ignore_private) { true }
      let(:password) { nil }
      specify  do
        expect { |b| collection.each(&b) }.to yield_successive_args(
          Metasploit::Framework::Credential.new(public: username, private: nil)
        )
      end

      context 'when :ignore_public is also true and username is nil' do
        let(:ignore_public) { true }
        let(:username) { nil }
        specify  do
          expect { |b| collection.each(&b) }.to yield_successive_args(
            Metasploit::Framework::Credential.new(public: nil, private: nil)
          )
        end
      end
    end

  end

  describe "#empty?" do
    context "when only :userpass_file is set" do
      let(:username) { nil }
      let(:password) { nil }
      let(:userpass_file) { "test_file" }
      specify do
        expect(collection.empty?).to eq false
      end
    end

    context "when :username is set" do
      context "and :password is set" do
        specify do
          expect(collection.empty?).to eq false
        end
      end

      context "and :password is not set" do
        let(:password) { nil }
        specify do
          expect(collection.empty?).to eq true
        end

        context "and :nil_passwords is true" do
          let(:nil_passwords) { true }
          specify do
            expect(collection.empty?).to eq false
          end
        end

        context "and :blank_passwords is true" do
          let(:blank_passwords) { true }
          specify do
            expect(collection.empty?).to eq false
          end
        end
      end
    end

    context "when :username is not set" do
      context "and :password is not set" do
        let(:username) { nil }
        let(:password) { nil }
        specify do
          expect(collection.empty?).to eq true
        end

        context "and :prepended_creds is not empty" do
          let(:prepended_creds) { [ "test" ] }
          specify do
            expect(collection.empty?).to eq false
          end
        end

        context "and :additional_privates is not empty" do
          let(:additional_privates) { [ "test_private" ] }
          specify do
            expect(collection.empty?).to eq true
          end
        end

        context "and :additional_publics is not empty" do
          let(:additional_publics) { [ "test_public" ] }
          specify do
            expect(collection.empty?).to eq true
          end
        end

        context "and :ignore_public is set" do
          let(:ignore_public) { true }
          specify do
            expect(collection.empty?).to eq true
          end

          context "and :ignore_private is also set" do
            let(:ignore_private) { true }
            specify do
              expect(collection.empty?).to eq false
            end
          end
        end

      end
    end
  end

  describe "#prepend_cred" do
    specify do
      prep = Metasploit::Framework::Credential.new(public: "foo", private: "bar")
      collection.prepend_cred(prep)
      expect { |b| collection.each(&b) }.to yield_successive_args(
        prep,
        Metasploit::Framework::Credential.new(public: username, private: password),
      )
    end
  end

end
