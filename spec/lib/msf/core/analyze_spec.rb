require 'spec_helper'

RSpec.describe Msf::Analyze do
  context '#group_vulns' do
    subject(:msf_analyze) { Msf::Analyze.new(nil) }
    let(:ref_1) { FactoryBot.create(:mdm_ref) }
    let(:ref_2) { FactoryBot.create(:mdm_ref) }
    let(:ref_3) { FactoryBot.create(:mdm_ref) }
    let(:ref_4) { FactoryBot.create(:mdm_ref) }

    let(:vuln_a) { FactoryBot.create(:mdm_vuln) }
    let(:vuln_a_dup_1) { FactoryBot.create(:mdm_vuln) }
    let(:vuln_b) { FactoryBot.create(:mdm_vuln) }
    let(:vuln_c) { FactoryBot.create(:mdm_vuln) }
    let(:vuln_c_transitive_to_a) { FactoryBot.create(:mdm_vuln) }
    let(:vuln_d) { FactoryBot.create(:mdm_vuln) }
    let(:vuln_d_transitive_to_c) { FactoryBot.create(:mdm_vuln) }

    let!(:vuln_a_refnames) do
      refs = [
        ref_1
      ]
      allow(vuln_a).to receive(:refs).and_return(refs)
      allow(vuln_a_dup_1).to receive(:refs).and_return(refs)

      refs.map { |r| r.name.upcase }
    end

    let!(:vuln_b_refnames) do
      refs = [
        ref_2
      ]
      allow(vuln_b).to receive(:refs).and_return(refs)

      refs.map { |r| r.name.upcase }
    end

    let!(:vuln_c_refnames) do
      refs = [
        ref_3
      ]
      allow(vuln_c).to receive(:refs).and_return(refs)

      refs.map { |r| r.name.upcase }
    end

    let!(:vuln_c_transitive_to_a_refnames) do
      refs = [
        ref_1,
        ref_3
      ]
      allow(vuln_c_transitive_to_a).to receive(:refs).and_return(refs)

      refs.map { |r| r.name.upcase }
    end

    let!(:vuln_d_refnames) do
      refs = [
        ref_4
      ]
      allow(vuln_d).to receive(:refs).and_return(refs)

      refs.map { |r| r.name.upcase }
    end

    let!(:vuln_d_transitive_to_c_refnames) do
      refs = [
        ref_4,
        ref_3
      ]
      allow(vuln_d_transitive_to_c).to receive(:refs).and_return(refs)

      refs.map { |r| r.name.upcase }
    end

    it 'should return an Array' do
      ret = subject.send(:group_vulns, [])
      expect(ret).to be_an(Array)
    end

    context 'with one vuln' do
      subject(:group_vulns) { msf_analyze.send(:group_vulns, [vuln_a]) }

      it 'should return two Sets per vuln family' do
        expect(subject.size).to be(1)
        expect(subject.first[0]).to be_a(Set)
        expect(subject.first[1]).to be_a(Set)
      end

      it 'should return the vuln' do
        expect(subject.first[0]).to eql(Set.new([vuln_a]))
      end

      it 'should return the upcased names of the refs in a set' do
        expect(subject.first[1]).to eql(Set.new(vuln_a_refnames))
      end
    end

    context 'with disjoint vulns' do
      subject(:group_vulns) { msf_analyze.send(:group_vulns, [vuln_a, vuln_b]) }

      it 'should return two Sets per vuln family' do
        expect(subject.size).to be(2)
        subject.each do |family|
          expect(family[0]).to be_a(Set)
          expect(family[1]).to be_a(Set)
        end
      end

      it 'should return the vulns separately' do
        expect(subject[0][0]).to eql(Set.new([vuln_a]))
        expect(subject[1][0]).to eql(Set.new([vuln_b]))
      end

      it 'should return the upcased names of the refs in separate sets' do
        expect(subject[0][1]).to eql(Set.new(vuln_a_refnames))
        expect(subject[1][1]).to eql(Set.new(vuln_b_refnames))
      end
    end

    context 'with overlapping vulns' do
      subject(:group_vulns) { msf_analyze.send(:group_vulns, [vuln_a, vuln_a_dup_1]) }

      it 'should return two Sets per vuln family' do
        expect(subject.size).to be(1)
        subject.each do |family|
          expect(family[0]).to be_a(Set)
          expect(family[1]).to be_a(Set)
        end
      end

      it 'should return the vulns together' do
        expect(subject[0][0]).to eql(Set.new([vuln_a, vuln_a_dup_1]))
      end

      it 'should return the upcased names of the refs in a set' do
        expect(subject[0][1]).to eql(Set.new(vuln_a_refnames))
      end
    end

    context 'with overlapping and disjoint vulns' do
      subject(:group_vulns) { msf_analyze.send(:group_vulns, [vuln_a, vuln_b, vuln_a_dup_1]) }

      it 'should return two Sets per vuln family' do
        expect(subject.size).to be(2)
        subject.each do |family|
          expect(family[0]).to be_a(Set)
          expect(family[1]).to be_a(Set)
        end
      end

      it 'should return the vulns with the same references together' do
        expect(subject[0][0]).to eql(Set.new([vuln_a, vuln_a_dup_1]))
        expect(subject[1][0]).to eql(Set.new([vuln_b]))
      end

      it 'should return the upcased names of the refs separate sets' do
        expect(subject[0][1]).to eql(Set.new(vuln_a_refnames))
        expect(subject[1][1]).to eql(Set.new(vuln_b_refnames))
      end
    end

    context 'with transitive vulns' do
      %w(vuln_a vuln_c vuln_c_transitive_to_a).permutation do |perm|
        context "in permutation #{perm.inspect}" do
          # On the one hand, we need to test all these permutations, on the
          # other I'm sorry.
          let(:vuln_permutation) { eval("[#{perm.join(',')}]") }
          subject(:group_vulns) { msf_analyze.send(:group_vulns, vuln_permutation) }

          it 'should return two Sets per vuln family' do
            expect(subject.size).to be(1)
            subject.each do |family|
              expect(family[0]).to be_a(Set)
              expect(family[1]).to be_a(Set)
            end
          end

          it 'should return the vulns together' do
            expect(subject[0][0]).to eql(Set.new(vuln_permutation))
          end

          it 'should return the upcased names of the refs a set' do
            expect(subject[0][1]).to eql(Set.new(vuln_a_refnames.concat(vuln_c_refnames)))
          end
        end
      end
    end

    context 'with double-transitive vulns' do
      %w(vuln_a vuln_c vuln_c_transitive_to_a vuln_d vuln_d_transitive_to_c).permutation do |perm|
        context "in permutation #{perm.inspect}" do
          # On the one hand, we need to test all these permutations, on the
          # other I'm sorry.
          let(:vuln_permutation) { eval("[#{perm.join(',')}]") }
          subject(:group_vulns) { msf_analyze.send(:group_vulns, vuln_permutation) }

          it 'should return two Sets per vuln family' do
            expect(subject.size).to be(1)
            subject.each do |family|
              expect(family[0]).to be_a(Set)
              expect(family[1]).to be_a(Set)
            end
          end

          it 'should return the vulns together' do
            expect(subject[0][0]).to eql(Set.new(vuln_permutation))
          end

          it 'should return the upcased names of the refs a set' do
            expect(subject[0][1]).to eql(Set.new(vuln_a_refnames.concat(vuln_c_refnames, vuln_d_refnames)))
          end
        end
      end
    end
  end
end
