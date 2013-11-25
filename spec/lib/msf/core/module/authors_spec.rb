require 'spec_helper'

describe Msf::Module::Authors do
  let(:metasploit_class) do
    Msf::Module
  end

  let(:metasploit_instance) do
    metasploit_class.new(
        'Author' => formatted_authors
    )
  end

  context '#authors' do
    subject(:authors) do
      metasploit_instance.authors
    end

    let(:name) do
      FactoryGirl.generate :metasploit_model_author_name
    end

    context 'with name once' do
      let(:formatted_authors) do
        name
      end
    end

    context 'with name twice' do
      context 'with no emails' do
        let(:formatted_authors) do
          [
              name,
              name
          ]
        end

        its(:length) { should == 1 }

        context 'Msf::Module::Author' do
          subject(:msf_module_author) do
            authors.first
          end

          it 'should have common name' do
            msf_module_author.name.should == name
          end

          its(:email) { should be_blank }
        end
      end

      context 'with same email on both' do
        let(:domain) do
          FactoryGirl.generate :metasploit_model_email_address_domain
        end

        let(:email) do
          "#{local}@#{domain}"
        end

        let(:formatted_authors) do
          2.times.collect {
            Msf::Module::Author.new(name, email).to_s
          }
        end

        let(:local) do
          FactoryGirl.generate :metasploit_model_email_address_local
        end

        its(:length) { should == 1 }

        context 'Msf::Module::Author' do
          subject(:msf_module_author) do
            authors.first
          end

          it 'should have common email' do
            msf_module_author.email.should == email
          end

          it 'should have common name' do
            msf_module_author.name.should == name
          end
        end
      end

      context 'with different emails on both' do
        let(:emails) do
          2.times.collect {
            domain = FactoryGirl.generate :metasploit_model_email_address_domain
            local = FactoryGirl.generate :metasploit_model_email_address_local

            "#{local}@#{domain}"
          }
        end

        let(:formatted_authors) do
          emails.collect { |email|
            Msf::Module::Author.new(name, email).to_s
          }
        end

        specify {
          expect {
            authors
          }.to raise_error(ArgumentError)
        }
      end

      context 'with email only on one' do
        let(:domain) do
          FactoryGirl.generate :metasploit_model_email_address_domain
        end

        let(:email) do
          "#{local}@#{domain}"
        end

        let(:formatted_authors) do
          [
              Msf::Module::Author.new(name, email).to_s,
              name
          ]
        end

        let(:local) do
          FactoryGirl.generate :metasploit_model_email_address_local
        end

        its(:length) { should == 1 }

        context 'Msf::Module::Author' do
          subject(:msf_module_author) do
            authors.first
          end

          it 'should have common name' do
            msf_module_author.name.should == name
          end

          it 'should have the only email' do
            msf_module_author.email.should == email
          end
        end
      end
    end
  end
end