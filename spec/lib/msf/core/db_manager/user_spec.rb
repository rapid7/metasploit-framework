require 'spec_helper'

RSpec.describe Msf::DBManager::User, skip: (ENV['REMOTE_DB'] ? 'The remote data service does not expose user methods' : false) do
  include_context 'Msf::DBManager'

  describe '#report_user' do
    let(:username) { 'report_user_spec' }
    let(:password) { 'Pw123456!' }

    subject(:user) { db_manager.report_user(opts) }

    context 'with permitted attributes' do
      let(:opts) { { username: username, password: password, admin: true, email: 'a@example.com', fullname: 'A B' } }

      it 'sets them' do
        expect(user).to have_attributes(username: username, admin: true, email: 'a@example.com', fullname: 'A B')
      end

      it 'hashes the password' do
        expect(BCrypt::Password.new(user.crypted_password)).to eq(password)
      end
    end

    context 'when the caller supplies attributes that are not client-settable' do
      let(:opts) do
        {
          username: username, password: password, persistence_token: 'attacker_token', sso_enabled: true,
          crypted_password: 'raw-hash', password_salt: 'salt'
        }
      end

      it 'does not set the persistence token' do
        expect(user.persistence_token).to be_nil
      end

      it 'does not set sso_enabled, the password hash or the salt from the request' do
        expect(user.sso_enabled).to be(false)
        expect(user.crypted_password).not_to eq('raw-hash')
        expect(user.password_salt).to be_nil
      end
    end

    context 'when admin is not supplied' do
      let(:opts) { { username: username, password: password } }

      it 'defaults to a non-admin user' do
        expect(user.admin).to be(false)
      end
    end

    context 'when called with bare keywords' do
      it 'creates the user' do
        expect(db_manager.report_user(username: username, password: password, admin: true)).to have_attributes(username: username, admin: true)
      end
    end

    context 'when the request data contains a trusted key' do
      let(:opts) { { username: username, password: password, trusted: true, persistence_token: 'attacker_token' } }

      it 'does not treat the data as trusted' do
        expect(user.persistence_token).to be_nil
      end
    end

    context 'when called as trusted' do
      subject(:user) { db_manager.report_user(opts, true) }

      let(:opts) do
        {
          username: username, password: password, persistence_token: 'restored_token', sso_enabled: true,
          password_salt: 'salt', crypted_password: 'raw-hash'
        }
      end

      it 'sets the persistence token, sso_enabled and the salt' do
        expect(user).to have_attributes(persistence_token: 'restored_token', sso_enabled: true, password_salt: 'salt')
      end

      it 'still derives the password hash from the password' do
        expect(BCrypt::Password.new(user.crypted_password)).to eq(password)
      end
    end
  end

  describe '#update_user' do
    let!(:existing_user) { db_manager.report_user(username: 'update_user_spec', password: 'Pw123456!') }

    subject(:updated_user) { db_manager.update_user(opts.merge(id: existing_user.id)) }

    context 'with permitted attributes' do
      let(:opts) { { email: 'a@example.com', company: 'Example', admin: true } }

      it 'updates them' do
        expect(updated_user).to have_attributes(email: 'a@example.com', company: 'Example', admin: true)
      end
    end

    context 'when the caller supplies attributes that are not client-settable' do
      let(:opts) do
        {
          email: 'a@example.com', persistence_token: 'attacker_token', sso_enabled: true,
          crypted_password: 'raw-hash', password_salt: 'salt'
        }
      end

      it 'does not set the persistence token' do
        expect(updated_user.persistence_token).to be_nil
      end

      it 'does not set sso_enabled, the password hash or the salt' do
        expect(updated_user).to have_attributes(sso_enabled: false, password_salt: nil, crypted_password: existing_user.crypted_password)
      end

      it 'still applies the permitted attributes' do
        expect(updated_user.email).to eq('a@example.com')
      end
    end
  end

  describe '#msf_import_user' do
    subject(:user) { db_manager.msf_import_user(opts) }

    let(:opts) do
      {
        username: 'import_user_spec', password: 'Pw123456!', admin: true, persistence_token: 'restored_token',
        sso_enabled: true, created_at: Time.utc(2024, 1, 1), updated_at: Time.utc(2024, 1, 1)
      }
    end

    it 'restores the persistence token and sso_enabled' do
      expect(user).to have_attributes(persistence_token: 'restored_token', sso_enabled: true, admin: true)
    end

    it 'keeps the imported timestamps' do
      expect(user).to have_attributes(created_at: Time.utc(2024, 1, 1), updated_at: Time.utc(2024, 1, 1))
    end
  end
end
