require 'spec_helper'

describe JSObfu::Scope do

  subject(:scope) do
    described_class.new
  end

  describe '#random_var_name' do
    # the number of iterations while testing randomness
    let(:n) { 20 }

    subject(:random_var_name) { scope.random_var_name }

    it { should be_a String }
    it { should_not be_empty }

    it 'is composed of _, $, alphanumeric chars' do
      n.times { expect(scope.random_var_name).to match(/\A[a-zA-Z0-9$_]+\Z/) }
    end

    it 'does not start with a number' do
      n.times { expect(scope.random_var_name).not_to match(/\A[0-9]/) }
    end

    context 'when a reserved word is generated' do
      let(:reserved)  { described_class::RESERVED_KEYWORDS.first }
      let(:random)    { 'abcdef' }
      let(:generated) { [reserved, reserved, reserved, random] }

      before do
        allow(scope).to receive(:random_string) { generated.shift }
      end

      it { should eq random }
    end

    context 'when a non-unique random var is generated' do
      let(:preexisting) { 'preexist' }
      let(:random)      { 'abcdef' }
      let(:generated)   { [preexisting, preexisting, preexisting, random] }

      before do
        allow(scope).to receive(:random_string) { generated.shift }
        scope[preexisting] = 1
      end

      it { should eq random }
    end
  end

  describe 'stack behavior' do
    context 'add a var to the Scope, then call #pop!' do
      let(:var_name) { 'a' }
      it 'no longer contains that var' do
        scope[var_name] = 1
        scope.pop!
        expect(scope).not_to have_key(var_name)
      end
    end

    context 'add a var to the Scope, then call #push!' do
      let(:var_name) { 'a' }
      it 'still contains that var' do
        scope[var_name] = 1
        scope.push!
        expect(scope).to have_key(var_name)
      end
    end

    context 'add a var to the Scope, call #push!, then call #pop!' do
      let(:var_name) { 'a' }
      it 'still contains that var' do
        scope[var_name] = 1
        scope.push!
        scope.pop!
        expect(scope).to have_key(var_name)
      end
    end

    context 'call #push!, add a var to the Scope, call #push!, then call #pop!' do
      let(:var_name) { 'a' }
      it 'still contains that var' do
        scope.push!
        scope[var_name] = 1
        scope.push!
        scope.pop!
        expect(scope).to have_key(var_name)
      end
    end

    context 'call #push!, add a var to the Scope, call #pop!, then call #push!' do
      let(:var_name) { 'a' }
      it 'no longer contains that var' do
        scope.push!
        scope[var_name] = 1
        scope.pop!
        scope.push!
        expect(scope).not_to have_key(var_name)
      end
    end

    context 'call #push!, add var1, call #push!, add var2, then call #pop!' do
      let(:var1) { 'a' }
      let(:var2) { 'b' }

      before do
        scope.push!
        scope[var1] = 1
        scope.push!
        scope[var2] = 1
        scope.pop!
      end

      it 'still contains var1' do
        expect(scope).to have_key(var1)
      end

      it 'no longer contains var2' do
        expect(scope).not_to have_key(var2)
      end
    end
  end

  describe '#rename_var' do
    context 'when called more than once on the same var' do
      let(:var) { 'a' }
      let(:n) { 10 }
      let(:first_rename) { scope.rename_var(var) }

      it 'returns the same result' do
        n.times { expect(scope.rename_var(var)).to eq first_rename }
      end
    end

    context 'when called on different vars' do
      let(:var1) { 'a' }
      let(:var2) { 'b' }
      let(:n) { 50 }

      it 'returns a different result' do
        n.times do
          scope = described_class.new
          expect(scope.rename_var(var1)).not_to eq scope.rename_var(var2)
        end
      end
    end

    context '#push!; #rename_var(a); #pop!; #rename_var(a)' do
      let(:var) { 'a' }
      let(:n)   { 50 }

      it 're-maps the vars to (usually) different random strings' do
        scope.push!
        first_var = scope.rename_var(var)
        scope.pop!
        n.times do
          new_var = scope.rename_var(var)
          if new_var == first_var # this is allowed to happen occasionally since shadowing is OK.
            next
          else
            expect(new_var).not_to eq first_var
          end
        end
      end
    end

    context '#push!; #push!; #rename_var(a); #pop!; #rename_var(a)' do
      let(:var) { 'a' }
      let(:n)   { 50 }

      it 're-maps the vars to (usually) different random strings' do
        scope.push!
        scope.push!
        first_var = scope.rename_var(var)
        scope.pop!
        n.times do
          new_var = scope.rename_var(var)
          if new_var == first_var # this is allowed to happen occasionally since shadowing is OK.
            next
          else
            expect(new_var).not_to eq first_var
          end
        end
      end
    end

    context '#rename_var(a); push!; #push!; #rename_var(a);' do
      let(:var) { 'a' }
      let(:n)   { 50 }

      it 're-maps the vars to the same random string' do
        first_var = scope.rename_var(var)
        scope.push!
        scope.push!
        expect(scope.rename_var(var)).to eq first_var
      end
    end
  end

end
