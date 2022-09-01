require 'rspec'

RSpec.shared_examples_for '#each_user_pass' do |options|
  let(:datastore) do
    options[:datastore].transform_values do |value|
      if value.is_a?(Array) && value[0] == :create_tempfile
        create_tempfile(value[1])
      else
        value
      end
    end
  end

  def create_tempfile(content)
    file = Tempfile.new
    @temp_files << file
    file.write(content)
    file.flush

    file.path
  end

  before do
    @temp_files = []
  end

  after do
    @temp_files.each(&:unlink)
  end

  context options[:context] do
    it 'yields each user_pass' do
      expect { |block| subject.each_user_pass(true, &block) }.to yield_successive_args(*options[:expected])
    end

    it 'stops on the first abort response' do
      if options[:expected].any?
        expect do |block|
          mock_proc = block.to_proc
          subject.each_user_pass(true) do |*args|
            mock_proc.call(*args)
            :abort
          end
        end.to yield_successive_args(options[:expected].first)
      else
        expect { |block| subject.each_user_pass(true, &block) }.not_to yield_control
      end
    end

    it 'calculates the size correctly' do
      subject.each_user_pass(true) do |_user, _pass|
        # noop
      end
      expect(subject.class.class_variable_get("@@max_per_service")).to eq(options[:expected_size])
    end
  end
end

RSpec.describe Msf::Auxiliary::AuthBrute do
  include_context 'Msf::DBManager'

  let(:subject) do
    described_class = self.described_class
    clazz = Class.new(Msf::Module) do
      # Contains `myworkspace` method which AuthBrute implicitly relies on
      include Msf::Auxiliary::Report
      include described_class

      def proto_from_fullname
        'mock_proto'
      end
    end
    mod = clazz.new
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:datastore).and_return(datastore)
    mod
  end

  let(:origin) { FactoryBot.build(:metasploit_credential_origin_import) }
  let(:priv) { FactoryBot.build(:metasploit_credential_password, data: 'db_pass') }
  let(:pub) { FactoryBot.build(:metasploit_credential_username, username: 'db_user') }
  let(:blank_pub) { FactoryBot.build(:metasploit_credential_blank_username) }
  let(:nonblank_priv) { FactoryBot.build(:metasploit_credential_password, data: 'db_nonblank_pass') }
  let(:nonblank_pub) { FactoryBot.build(:metasploit_credential_username, username: 'db_nonblank_user') }
  let(:blank_priv) { FactoryBot.build(:metasploit_credential_password, data: '') }

  before(:example) do
    allow(framework).to receive(:db).and_call_original
    allow(framework.db).to receive(:creds).and_return(
      [
        FactoryBot.build(
          :metasploit_credential_core,
          origin: origin,
          private: priv,
          public: pub,
          realm: nil,
          workspace: framework.db.workspace
        ),

        FactoryBot.build(
          :metasploit_credential_core,
          origin: origin,
          private: nonblank_priv,
          public: blank_pub,
          realm: nil,
          workspace: framework.db.workspace
        ),

        FactoryBot.build(
          :metasploit_credential_core,
          origin: origin,
          private: blank_priv,
          public: nonblank_pub,
          realm: nil,
          workspace: framework.db.workspace
        )
      ]
    )
  end

  # Convenience method which defers the creation of a temporary file until its needed as
  # part of a test
  def self.tempfile(content)
    [:create_tempfile, content]
  end

  describe '#each_user_pass' do
    context 'when noconn is true' do
      context 'when no options are provided' do
        it_behaves_like(
          '#each_user_pass',
          context: 'when no options are provided',
          datastore: {
            'TRANSITION_DELAY' => 0
          },
          expected: [],
          expected_size: 0
        )
      end

      context 'when USERNAME and PASSWORD are provided' do
        it_behaves_like(
          '#each_user_pass',
          context: 'when username and password are provided',
          datastore: {
            'USERNAME' => 'user1',
            'PASSWORD' => 'pass1',
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass1'],
          ],
          expected_size: 1
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when username and password are provided',
          datastore: {
            'USERNAME' => 'user1',
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', ''],
          ],
          expected_size: 1
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when username and password are provided',
          datastore: {
            'PASSWORD' => 'pass1',
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['', 'pass1'],
          ],
          expected_size: 1
        )
      end

      context 'when USER_FILE and PASS_FILE are provided' do
        it_behaves_like(
          '#each_user_pass',
          context: 'when pass_file is empty',
          datastore: {
            'USER_FILE' => tempfile("user1\nuser2\n"),
            'PASS_FILE' => tempfile(''),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', ''],
            ['user2', '']
          ],
          expected_size: 2
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when both files have content',
          datastore: {
            'USER_FILE' => tempfile("user1\nuser2\n"),
            'PASS_FILE' => tempfile("pass1\npass2\npass3"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass1'],
            ['user1', 'pass2'],
            ['user1', 'pass3'],
            ['user2', 'pass1'],
            ['user2', 'pass2'],
            ['user2', 'pass3']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when both files have content and PASSWORD_SPRAY is set as true',
          datastore: {
            'USER_FILE' => tempfile("user1\nuser2\n"),
            'PASS_FILE' => tempfile("pass1\npass2\npass3"),
            'PASSWORD_SPRAY' => true,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass1'],
            ['user2', 'pass1'],
            ['user1', 'pass2'],
            ['user2', 'pass2'],
            ['user1', 'pass3'],
            ['user2', 'pass3']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when both files have content and PASSWORD_SPRAY is set as false',
          datastore: {
            'USER_FILE' => tempfile("user1\nuser2\n"),
            'PASS_FILE' => tempfile("pass1\npass2\npass3"),
            'PASSWORD_SPRAY' => false,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass1'],
            ['user1', 'pass2'],
            ['user1', 'pass3'],
            ['user2', 'pass1'],
            ['user2', 'pass2'],
            ['user2', 'pass3']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when there is both a new line and carriage return',
          datastore: {
            'USER_FILE' => tempfile("user1\r\nuser2\r\n"),
            'PASS_FILE' => tempfile("pass1\r\npass2\r\npass3"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass1'],
            ['user1', 'pass2'],
            ['user1', 'pass3'],
            ['user2', 'pass1'],
            ['user2', 'pass2'],
            ['user2', 'pass3']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the username field is provided, it is prioritized',
          datastore: {
            'USERNAME' => 'user3',
            'USER_FILE' => tempfile("user1\nuser2\nuser3"),
            'PASS_FILE' => tempfile("pass1\npass2"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user3', 'pass1'],
            ['user3', 'pass2'],
            ['user1', 'pass1'],
            ['user1', 'pass2'],
            ['user2', 'pass1'],
            ['user2', 'pass2']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the password field is provided, it is prioritized',
          datastore: {
            'PASSWORD' => 'pass2',
            'USER_FILE' => tempfile("user1\nuser2\nuser3"),
            'PASS_FILE' => tempfile("pass1\npass2"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass2'],
            ['user2', 'pass2'],
            ['user3', 'pass2'],
            ['user1', 'pass1'],
            ['user2', 'pass1'],
            ['user3', 'pass1']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when both username password fields are provided, they are prioritized',
          datastore: {
            'USERNAME' => 'user3',
            'PASSWORD' => 'pass2',
            'USER_FILE' => tempfile("user1\nuser2\nuser3"),
            'PASS_FILE' => tempfile("pass1\npass2"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user3', 'pass2'],
            ['user1', 'pass2'],
            ['user2', 'pass2'],
            ['user3', 'pass1'],
            ['user1', 'pass1'],
            ['user2', 'pass1']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the pass file does not exist',
          datastore: {
            'USER_FILE' => tempfile("user1\nuser2\nuser3"),
            'PASS_FILE' => File.expand_path('nonexistant_file.txt', FILE_FIXTURES_PATH),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', ''],
            ['user2', ''],
            ['user3', '']
          ],
          expected_size: 3
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the user file does not exist',
          datastore: {
            'USER_FILE' => File.expand_path('nonexistant_file.txt', FILE_FIXTURES_PATH),
            'PASS_FILE' => tempfile("pass1\npass2\npass3"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['', 'pass1'],
            ['', 'pass2'],
            ['', 'pass3']
          ],
          expected_size: 3
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the the user / password files contain duplicate values',
          datastore: {
            'USER_FILE' => tempfile("user1\nuser2\nuser3\n" * 3),
            'PASS_FILE' => tempfile("pass1\npass2\npass3\n" * 3),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'pass1'],
            ['user1', 'pass2'],
            ['user1', 'pass3'],
            ['user2', 'pass1'],
            ['user2', 'pass2'],
            ['user2', 'pass3'],
            ['user3', 'pass1'],
            ['user3', 'pass2'],
            ['user3', 'pass3']
          ],
          expected_size: 9
        )
      end

      context 'when USERPASS_FILE is provided' do
        it_behaves_like(
          '#each_user_pass',
          context: 'when the file has passwords containing spaces',
          datastore: {
            'USERPASS_FILE' => tempfile("user1 foo\nuser1 foo bar\n"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'foo'],
            ['user1', 'foo bar']
          ],
          expected_size: 2
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the file has passwords containing spaces and BLANK_PASSWORDS is set',
          datastore: {
            'USERPASS_FILE' => tempfile("user1 foo\nuser1 foo bar\nuser2\nuser3 foo"),
            'BLANK_PASSWORDS' => true,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', ''],
            ['user2', ''],
            ['user3', ''],
            ['user1', 'foo'],
            ['user1', 'foo bar'],
            ['user3', 'foo']
          ],
          expected_size: 6
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when the file has passwords containing spaces',
          datastore: {
            'USERPASS_FILE' => tempfile("user1 foo\nuser1 foo bar\n"),
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', 'foo'],
            ['user1', 'foo bar']
          ],
          expected_size: 2
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when MaxGuessesPerUser is set',
          datastore: {
            'USERPASS_FILE' => tempfile("user1 foo\nuser1 foo bar\nuser2\nuser3 foo"),
            'BLANK_PASSWORDS' => true,
            'MaxGuessesPerUser' => 2,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', ''],
            ['user2', ''],
            ['user3', ''],
            ['user1', 'foo'],
            ['user3', 'foo']
          ],
          expected_size: 5
        )
      end

      context 'when database options are set' do
        it_behaves_like(
          '#each_user_pass',
          context: 'when DB_ALL_CREDS is set',
          datastore: {
            'DB_ALL_CREDS' => true,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['db_user', 'db_pass'],
            ['', 'db_nonblank_pass'],
            ['db_nonblank_user', '']
          ],
          expected_size: 3
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when DB_ALL_USERS is set',
          datastore: {
            'DB_ALL_USERS' => true,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['db_user', ''],
            ['', ''],
            ['db_nonblank_user', '']
          ],
          expected_size: 3
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when DB_ALL_PASS is set',
          datastore: {
            'DB_ALL_PASS' => true,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['', 'db_pass'],
            ['', 'db_nonblank_pass'],
            ['', '']
          ],
          expected_size: 3
        )

        it_behaves_like(
          '#each_user_pass',
          context: 'when all DB_* options are set',
          datastore: {
            'DB_ALL_CREDS' => true,
            'DB_ALL_PASS' => true,
            'DB_ALL_USERS' => true,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['db_user', 'db_pass'],
            ['', 'db_nonblank_pass'],
            ['db_nonblank_user', ''],
            ['db_user', 'db_nonblank_pass'],
            ['db_user', ''],
            ['', 'db_pass'],
            ['', ''],
            ['db_nonblank_user', 'db_pass'],
            ['db_nonblank_user', 'db_nonblank_pass']
          ],
          expected_size: 9
        )
      end

      context 'when the most combinations of options are set' do
        it_behaves_like(
          '#each_user_pass',
          context: 'user/pass and database options are provided',
          datastore: {
            'USER_FILE' => tempfile("user1\r\nuser2\r\n"),
            'PASS_FILE' => tempfile("pass1\r\npass2\r\npass3"),
            'USERPASS_FILE' => tempfile("user_a pass_a\nuser_b pass_b\n"),
            'USER_AS_PASS' => true,
            'BLANK_PASSWORDS' => true,
            'DB_ALL_CREDS' => true,
            'DB_ALL_USERS' => true,
            'DB_ALL_PASS' => true,
            'VERBOSE' => true,
            'MaxGuessesPerUser' => 5,
            'TRANSITION_DELAY' => 0
          },
          expected: [
            ['user1', ''],
            ['user2', ''],
            ['user_a', ''],
            ['user_b', ''],
            ['user1', 'user1'],
            ['user2', 'user2'],
            ['user_a', 'user_a'],
            ['user_b', 'user_b'],
            ['user_a', 'pass_a'],
            ['user_b', 'pass_b'],
            ['db_user', 'db_pass'],
            ['', 'db_nonblank_pass'],
            ['db_nonblank_user', ''],
            ['user1', 'pass1'],
            ['user1', 'pass2'],
            ['user1', 'pass3'],
            ['user2', 'pass1'],
            ['user2', 'pass2'],
            ['user2', 'pass3'],
            ['db_user', 'pass1'],
            ['db_user', 'pass2'],
            ['db_user', 'pass3'],
            ['db_user', 'db_nonblank_pass'],
            ['', 'pass1'],
            ['', 'pass2'],
            ['', 'pass3'],
            ['', 'db_pass'],
            ['db_nonblank_user', 'pass1'],
            ['db_nonblank_user', 'pass2'],
            ['db_nonblank_user', 'pass3'],
            ['db_nonblank_user', 'db_pass']
          ],
          expected_size: 31
        )
      end
    end
  end
end
