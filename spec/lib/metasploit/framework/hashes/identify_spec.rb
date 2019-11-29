require 'spec_helper'
require 'metasploit/framework/hashes/identify'
require 'bcrypt'

=begin
#!/usr/bin/python
# bcrypts generated with python's passlib
from passlib import hash
print("MD5: %s") %(hash.md5_crypt.hash("password"))
print("BCrypt 2: %s") %(hash.bcrypt.using(ident="2").hash("password"))
print("BCrypt 2a: %s") %(hash.bcrypt.using(ident="2a").hash("password"))
print("BCrypt 2b: %s") %(hash.bcrypt.using(ident="2b").hash("password"))
print("BCrypt 2y: %s") %(hash.bcrypt.using(ident="2y").hash("password"))
# bcrypt.using(ident="2x").hash("password")
print("SHA256: %s") %(hash.sha256_crypt.hash("password"))
print("SHA512: %s") %(hash.sha512_crypt.hash("password"))
print("BSDi: %s") %(hash.bsdi_crypt.hash("password"))
print("DES: %s") %(hash.des_crypt.hash("password"))
=end

RSpec.describe 'hashes/identify' do

  describe 'identify_md5' do
    it 'returns md5' do
      hash = identify_hash('$1$IEHUWAxH$nMC1edxSFa4SaKH7hi2.P1')
      expect(hash).to match('md5')
    end
  end

  describe 'identify_blofish' do
    it 'returns bf' do
      hash = identify_hash('$2$12$YuKGRH4GwF0PoeS9ZGsxyucAw4ju7LUUm6zllt85HeleuKBRb0n5G')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_a' do
    it 'returns bf' do
      # looks like BCrypt can only generate 2a in ruby as of april 2019
      hash = identify_hash(BCrypt::Password.create("password"))
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_b' do
    it 'returns bf' do
      hash = identify_hash('$2b$12$LQRJHRdK8ubs.dOWBFc/6uhNNeuwMNzEBxjG5YSFu3swmnk2pMtSq')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_x' do
    it 'returns bf' do
      hash = identify_hash('$2x$12$LQRJHRdK8ubs.dOWBFc/6uhNNeuwMNzEBxjG5YSFu3swmnk2pMtSq')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_y' do
    it 'returns bf' do
      hash = identify_hash('$2y$12$EMrTs6wKK3Qj4u7jPL59Bug9JHBGhZKnZxTYKQAE9CEFBq9mDmfL2')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_sha256_rounds' do
    it 'returns sha256,crypt' do
      hash = identify_hash('$5$rounds=535000$28N3kN/W4y.z/VwS$jpaW4.rR/57IlqhJRpZDu9FoZu/jr.ksbRJJZjJSZN7')
      expect(hash).to match('sha256,crypt')
    end
  end

  describe 'identify_sha512_rounds' do
    it 'returns sha512,crypt' do
      hash = identify_hash('$6$rounds=656000$bnopPiXhQ2jjaa9h$H9.hNSwpg5PaUTtEEgTAjoZFsUKmONplIXLFe1nd0/QTyw/DMQhHuyChA2glT.BbYe9gJjE5RD.yog8Z5tACA/')
      expect(hash).to match('sha512,crypt')
    end
  end

  describe 'identify_sha512_norounds' do
    it 'returns sha512,crypt' do
      hash = identify_hash('$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/')
      expect(hash).to match('sha512,crypt')
    end
  end

  describe 'identify_qnx_sha256' do
    it 'returns qnx,sha256' do
      hash = identify_hash('@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604')
      expect(hash).to match('qnx,sha256')
    end
  end

  describe 'identify_qnx_sha512' do
    it 'returns qnx,sha512' do
      hash = identify_hash('@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159')
      expect(hash).to match('qnx,sha512')
    end
  end

  describe 'identify_qnx_md5' do
    it 'returns qnx,md5' do
      hash = identify_hash('@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050')
      expect(hash).to match('qnx,md5')
    end
  end

  describe 'identify_bsdi' do
    it 'returns des,bsdi,crypt' do
      hash = identify_hash('_7C/.WncdBNA9AL2CyaM')
      expect(hash).to match('des,bsdi,crypt')
    end
  end

  describe 'identify_des' do
    it 'returns des,crypt' do
      hash = identify_hash('ItkroId4UAOF.')
      expect(hash).to match('des,crypt')
    end
  end

  describe 'identify_pbkdf2_osx' do
    it 'returns pbkdf2-hmac-sha512,osx' do
      hash = identify_hash('$ml$49504$0dba6246bd38266b2e827ff7e7271380757c71d653893aa361d5902398302369$c5f198639915a101c99af326dffe13e8f14456be8fd2312a39a777b92178804e204ca4fee12a8667871440eff4288e811d86d746c6d96a60c919c3418dfebba42f329f5d73c0372d636d61d5dfda1add61af36c70e4acd771276107209e643ae92a0f43e95a452744e50fb4540d9bdf4e0b701725d7db488fbe18c1ab7737c6b')
      expect(hash).to match ('pbkdf2-hmac-sha512,osx')
    end
  end

  describe 'identify_sha_osx' do
    it 'returns xsha,osx' do
      hash = identify_hash('1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683')
      expect(hash).to match ('xsha,osx')
    end
  end

  describe 'identify_mssql05' do
    it 'returns mssql05' do
      hash = identify_hash('0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908')
      expect(hash).to match('mssql05')
    end
  end

  describe 'identify_mssql' do
    it 'returns mssql' do
      hash = identify_hash('0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254')
      expect(hash).to match('mssql')
    end
  end

  describe 'identify_mssql12' do
    it 'returns mssql12' do
      hash = identify_hash('0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16')
      expect(hash).to match('mssql12')
    end
  end

  describe 'identify_mysql' do
    it 'returns mysql' do
      hash = identify_hash('6f8c114b58f2ce9e')
      expect(hash).to match('mysql')
    end
  end

  describe 'identify_mysql_sha1' do
    it 'returns mysql_sha1' do
      hash = identify_hash('*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4')
      expect(hash).to match('mysql-sha1')
    end
  end

  describe 'identify_lanman' do
    it 'returns lm' do
      hash = identify_hash('E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C')
      expect(hash).to match('lm')
    end
  end

  describe 'identify_ntlm' do
    it 'returns nt' do
      hash = identify_hash('AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C')
      expect(hash).to match('nt')
    end
  end

  describe 'identify_postgres' do
    it 'returns postgres' do
      hash = identify_hash('md5be86a79bf2043622d58d5453c47d4860')
      expect(hash).to match('postgres')
    end
  end

  describe 'identify_oracle_des' do
    it 'returns des,oracle' do
      hash = identify_hash('4F8BC1809CB2AF77')
      expect(hash).to match('des,oracle')
    end
  end

  describe 'identify_oracle11_S' do
    it 'returns raw-sha1,oracle' do
      hash = identify_hash('S:BFAF1ED5A8D39CC10D07DAF03A175C65198359874DAD92F081BE09B89162')
      expect(hash).to match('raw-sha1,oracle')
    end
  end

  describe 'identify_oracle_SHT' do
    it 'returns raw-sha1,oracle' do
      hash = identify_hash('S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C')
      expect(hash).to match('raw-sha1,oracle')
    end
  end

  describe 'identify_oracle_HT' do
    it 'returns ' do
      hash = identify_hash('H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C')
      expect(hash).to match('pbkdf2,oracle12c')
    end
  end

  describe 'identify_phpass_P' do
    it 'returns phpass' do
      hash = identify_hash('$P$984478476IagS59wHZvyQMArzfx58u.')
      expect(hash).to match('phpass')
    end
  end

  describe 'identify_phpass_H' do
    it 'returns phpass' do
      hash = identify_hash('$H$984478476IagS59wHZvyQMArzfx58u.')
      expect(hash).to match('phpass')
    end
  end

  describe 'identify_PBKDF2-HMAC-SHA512' do
    it 'returns PBKDF2-HMAC-SHA512' do
      hash = identify_hash('$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222')
      expect(hash).to match('PBKDF2-HMAC-SHA512')
    end
  end

  describe 'identify_PBKDF2-HMAC-SHA1' do
    it 'returns PBKDF2-HMAC-SHA1' do
      hash = identify_hash('{PKCS5S2}8WEZjkCbLWysbcbZ5PRgMbdJgJOhkzRT3y1jxOqke2z1Zr79q8ypugFQEYaMoIZt')
      expect(hash).to match('PBKDF2-HMAC-SHA1')
    end
  end

  describe 'identify_mediawiki' do
    it 'returns mediawiki' do
      hash = identify_hash('$B$113$de2874e33da25313d808d2a8cbf31485')
      expect(hash).to match('mediawiki')
    end
  end

  describe 'identify_android_sha1' do
    it 'returns android-sha1' do
      hash = identify_hash('EA8457DE97836C955082AE77DBE2CD86A4E8BC0E:4aafc54dc502e88b')
      expect(hash).to match ('android-sha1')
    end
  end

  describe 'identify_empty_string' do
    it 'returns empty string' do
      hash = identify_hash('')
      expect(hash).to match('')
    end
  end

  describe 'identify_nil' do
    it 'returns empty string' do
      hash = identify_hash(nil)
      expect(hash).to match('')
    end
  end

  describe 'identify_shadow_line' do
    it 'returns empty string' do
      hash = identify_hash('root:$1$TDQFedzX$.kv51AjM.FInu0lrH1dY30:15045:0:99999:7:::')
      expect(hash).to match('')
    end
  end

  describe 'identify_un_pass' do
    it 'returns empty string' do
      hash = identify_hash('root:$1$TDQFedzX$.kv51AjM.FInu0lrH1dY30')
      expect(hash).to match('')
    end
  end

  describe 'identify_ascii_as_nothing' do
    it 'returns empty string' do
      hash = identify_hash('This is just some words')
      expect(hash).to match('')
    end
  end

end
