RSpec.shared_examples_for 'a module with valid metadata' do
  #
  # Acceptable Stability ratings
  #
  valid_stability_values = [
    Msf::CRASH_SAFE,
    Msf::CRASH_SERVICE_RESTARTS,
    Msf::CRASH_SERVICE_DOWN,
    Msf::CRASH_OS_RESTARTS,
    Msf::CRASH_OS_DOWN,
    Msf::SERVICE_RESOURCE_LOSS,
    Msf::OS_RESOURCE_LOSS
  ]

  #
  # Acceptable Side-effect ratings
  #
  valid_side_effect_values = [
    Msf::ARTIFACTS_ON_DISK,
    Msf::CONFIG_CHANGES,
    Msf::IOC_IN_LOGS,
    Msf::ACCOUNT_LOCKOUTS,
    Msf::SCREEN_EFFECTS,
    Msf::AUDIO_EFFECTS,
    Msf::PHYSICAL_EFFECTS
  ]

  #
  # Acceptable Reliability ratings
  #
  valid_reliability_values = [
    Msf::FIRST_ATTEMPT_FAIL,
    Msf::REPEATABLE_SESSION,
    Msf::UNRELIABLE_SESSION
  ]

  #
  # Acceptable site references
  #
  valid_ctx_id_values = [
    'CVE',
    'CWE',
    'BID',
    # milw0rm references are no longer supported.
    # 'MIL',
    'MSB',
    'EDB',
    'US-CERT-VU',
    'ZDI',
    'URL',
    'WPVDB',
    'PACKETSTORM',
    'LOGO',
    'SOUNDTRACK',
    'OSVDB',
    # Issued by Veritas
    'VTS',
    # Openwall - https://www.openwall.com/ove/
    'OVE'
  ]

  #
  # Module name bad characters
  #
  module_name_bad_chars = %w[& < = >]

  # RSpec's API doesn't support a way to to not run tests without them appearing as 'skipped' in the console output
  def mark_as_passed(example)
    example.instance_variable_set(:@executed, true)
  end

  around(:each, :has_notes) do |example|
    if subject.notes.empty?
      mark_as_passed(example)
    else
      example.run
    end
  end

  around(:each, :has_excellent_ranking) do |example|
    if subject.rank_to_s == 'excellent'
      example.run
    else
      mark_as_passed(example)
    end
  end

  around(:each, :is_an_exploit) do |example|
    # Only exploits require notes
    if subject.exploit?
      example.run
    else
      mark_as_passed(example)
    end
  end

  around(:each, :is_a_payload) do |example|
    # Only exploits require notes
    if subject.payload?
      example.run
    else
      mark_as_passed(example)
    end
  end


  context 'when notes are present', :has_notes do
    describe '#stability' do
      context 'when the module has an excellent stability rating', :has_excellent_ranking do
        it 'has valid Stability notes values' do
          expect(subject.stability).to be_kind_of(Array)
          expect(subject.stability - valid_stability_values).to be_empty
        end

        it 'includes crash-safe in the stability notes' do
          expect(subject.stability).to include('crash-safe')
        end
      end
    end

    describe '#side_effects' do
      it 'has valid Side Effect notes values' do
        expect(subject.side_effects).to be_kind_of(Array)
        expect(subject.side_effects - valid_side_effect_values).to be_empty
      end
    end

    describe '#reliability' do
      it 'has valid Reliability notes values' do
        expect(subject.reliability).to be_kind_of(Array)
        expect(subject.reliability - valid_reliability_values).to be_empty
      end
    end
  end

  describe '#references' do
    context 'the module' do
      it 'has valid References values' do
        expect(subject.references).to be_kind_of(Array)
        references_ctx_id_list = []
        subject.references.each { |ref| references_ctx_id_list << ref.ctx_id }
        expect(references_ctx_id_list - valid_ctx_id_values).to be_empty
      end

      # it 'has a CVE present', :is_an_exploit do
      #   references_ctx_id_list = []
      #   required_references = %w[CVE BID ZDI MSB WPVDB EDB]
      #   subject.references.each { |ref| references_ctx_id_list << ref.ctx_id }
      #
      #   # if !references_ctx_id_list.include?(acceptable_refs)
      #   #   $stderr.puts subject.file_path
      #   # end
      #
      #   expect(references_ctx_id_list & required_references).to_not be_empty
      # end
    end
  end

  describe '#license' do
    context 'the module' do
      it 'has a valid license value' do
        expect(subject.license).to be_in(LICENSES)
      end
    end
  end

  describe '#ranking' do
    context 'when the module has a ranking present' do
      it 'has a valid ranking value' do
        expect(subject.rank).to be_in(Msf::RankingName.keys)
      end
    end
  end

  describe '#authors' do
    context 'the module' do
      it 'has valid authors values' do
        expect(subject.references).to be_kind_of(Array)
        expect(subject.author).to_not be_empty
      end
    end
  end

  describe '#name' do
    context 'the module name' do
      it ' should not contain bad characters' do
        expect(subject.name).to_not include(*module_name_bad_chars)
      end
    end
  end

  describe '#file_path' do
    context 'when the module has a file path' do
      let(:module_path) do
        subject.file_path.split('/').last
      end

      it 'should be snake case' do
        expect(module_path).to match(/^[a-z0-9]+(?:_[a-z0-9]+)*\.rb$/)
      end

      # Not sure if this is needed as it is caught in the above regex.
      # Will leave here for now as I am attempting to replicate `msftidy.rb` which
      # may be allowing for edges I haven't considered
      it "should a '.rb' file" do
        expect(module_path).to end_with('.rb')
      end
    end
  end

  # ## TODO - Need to figure out if this can be moved from `msfidy.rb` or not
  # describe '#disclosure_date' do
  #   context 'the module' do
  #     it 'has a disclosure date present', :is_an_exploit do
  #       expect(subject.disclosure_date).to be_kind_of(Date)
  #     end
  #   end
  # end

  describe '#description' do
    context 'the module' do
      it 'has a description present', :is_a_payload do
        expect(subject.description).to be_kind_of(String)
        expect(subject.description).to_not be_empty
      end
    end
  end

  ## TODO - As of 21/03/2023
  #         3534 examples, 1857 failures
  # describe '#notes' do
  #   context 'the module' do
  #     it 'has notes present', focus: true do
  #       # Only exploits require notes
  #       next unless subject.exploit?
  #
  #       # expect(subject.notes).to be_kind_of(Hash)
  #       expect(subject.notes).to_not be_empty
  #     end
  #   end
  # end
end
