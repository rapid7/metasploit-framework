require 'spec_helper'
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

RSpec.describe Metasploit::Framework::Hashes do
  describe 'identify_md5' do
    it 'returns md5' do
      hash = described_class.identify_hash('$1$IEHUWAxH$nMC1edxSFa4SaKH7hi2.P1')
      expect(hash).to match('md5')
    end
  end

  describe 'identify_blofish' do
    it 'returns bf' do
      hash = described_class.identify_hash('$2$12$YuKGRH4GwF0PoeS9ZGsxyucAw4ju7LUUm6zllt85HeleuKBRb0n5G')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_a' do
    it 'returns bf' do
      # looks like BCrypt can only generate 2a in ruby as of april 2019
      hash = described_class.identify_hash(BCrypt::Password.create('password'))
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_b' do
    it 'returns bf' do
      hash = described_class.identify_hash('$2b$12$LQRJHRdK8ubs.dOWBFc/6uhNNeuwMNzEBxjG5YSFu3swmnk2pMtSq')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_x' do
    it 'returns bf' do
      hash = described_class.identify_hash('$2x$12$LQRJHRdK8ubs.dOWBFc/6uhNNeuwMNzEBxjG5YSFu3swmnk2pMtSq')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_blofish_y' do
    it 'returns bf' do
      hash = described_class.identify_hash('$2y$12$EMrTs6wKK3Qj4u7jPL59Bug9JHBGhZKnZxTYKQAE9CEFBq9mDmfL2')
      expect(hash).to match('bf')
    end
  end

  describe 'identify_sha256_rounds' do
    it 'returns sha256,crypt' do
      hash = described_class.identify_hash('$5$rounds=535000$28N3kN/W4y.z/VwS$jpaW4.rR/57IlqhJRpZDu9FoZu/jr.ksbRJJZjJSZN7')
      expect(hash).to match('sha256,crypt')
    end
  end

  describe 'identify_sha512_rounds' do
    it 'returns sha512,crypt' do
      hash = described_class.identify_hash('$6$rounds=656000$bnopPiXhQ2jjaa9h$H9.hNSwpg5PaUTtEEgTAjoZFsUKmONplIXLFe1nd0/QTyw/DMQhHuyChA2glT.BbYe9gJjE5RD.yog8Z5tACA/')
      expect(hash).to match('sha512,crypt')
    end
  end

  describe 'identify_sha512_norounds' do
    it 'returns sha512,crypt' do
      hash = described_class.identify_hash('$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/')
      expect(hash).to match('sha512,crypt')
    end
  end

  describe 'identify_qnx_sha256' do
    it 'returns qnx,sha256' do
      hash = described_class.identify_hash('@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604')
      expect(hash).to match('qnx,sha256')
    end
  end

  describe 'identify_qnx_sha512' do
    it 'returns qnx,sha512' do
      hash = described_class.identify_hash('@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159')
      expect(hash).to match('qnx,sha512')
    end
  end

  describe 'identify_qnx_md5' do
    it 'returns qnx,md5' do
      hash = described_class.identify_hash('@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050')
      expect(hash).to match('qnx,md5')
    end
  end

  describe 'identify_bsdi' do
    it 'returns des,bsdi,crypt' do
      hash = described_class.identify_hash('_7C/.WncdBNA9AL2CyaM')
      expect(hash).to match('des,bsdi,crypt')
    end
  end

  describe 'identify_des' do
    it 'returns des,crypt' do
      hash = described_class.identify_hash('ItkroId4UAOF.')
      expect(hash).to match('des,crypt')
    end
  end

  describe 'identify_pbkdf2_osx' do
    it 'returns pbkdf2-hmac-sha512,osx' do
      hash = described_class.identify_hash('$ml$49504$0dba6246bd38266b2e827ff7e7271380757c71d653893aa361d5902398302369$c5f198639915a101c99af326dffe13e8f14456be8fd2312a39a777b92178804e204ca4fee12a8667871440eff4288e811d86d746c6d96a60c919c3418dfebba42f329f5d73c0372d636d61d5dfda1add61af36c70e4acd771276107209e643ae92a0f43e95a452744e50fb4540d9bdf4e0b701725d7db488fbe18c1ab7737c6b')
      expect(hash).to match('pbkdf2-hmac-sha512,osx')
    end
  end

  describe 'identify_sha_osx' do
    it 'returns xsha,osx' do
      hash = described_class.identify_hash('1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683')
      expect(hash).to match('xsha,osx')
    end
  end

  describe 'identify_mssql05' do
    it 'returns mssql05' do
      hash = described_class.identify_hash('0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908')
      expect(hash).to match('mssql05')
    end
  end

  describe 'identify_mssql' do
    it 'returns mssql' do
      hash = described_class.identify_hash('0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254')
      expect(hash).to match('mssql')
    end
  end

  describe 'identify_mssql12' do
    it 'returns mssql12' do
      hash = described_class.identify_hash('0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16')
      expect(hash).to match('mssql12')
    end
  end

  describe 'identify_mysql' do
    it 'returns mysql' do
      hash = described_class.identify_hash('6f8c114b58f2ce9e')
      expect(hash).to match('mysql')
    end
  end

  describe 'identify_mysql_sha1' do
    it 'returns mysql_sha1' do
      hash = described_class.identify_hash('*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4')
      expect(hash).to match('mysql-sha1')
    end
  end

  describe 'identify_lanman' do
    it 'returns lm' do
      hash = described_class.identify_hash('E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C')
      expect(hash).to match('lm')
    end
  end

  describe 'identify_ntlm' do
    it 'returns nt' do
      hash = described_class.identify_hash('AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C')
      expect(hash).to match('nt')
    end
  end

  describe 'identify_postgres' do
    it 'returns postgres' do
      hash = described_class.identify_hash('md5be86a79bf2043622d58d5453c47d4860')
      expect(hash).to match('postgres')
    end
  end

  describe 'identify_oracle_des' do
    it 'returns des,oracle' do
      hash = described_class.identify_hash('4F8BC1809CB2AF77')
      expect(hash).to match('des,oracle')
    end
  end

  describe 'identify_oracle11_S' do
    it 'returns raw-sha1,oracle' do
      hash = described_class.identify_hash('S:BFAF1ED5A8D39CC10D07DAF03A175C65198359874DAD92F081BE09B89162')
      expect(hash).to match('raw-sha1,oracle')
    end
  end

  describe 'identify_oracle_SHT' do
    it 'returns raw-sha1,oracle' do
      hash = described_class.identify_hash('S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C')
      expect(hash).to match('raw-sha1,oracle')
    end
  end

  describe 'identify_oracle_HT' do
    it 'returns ' do
      hash = described_class.identify_hash('H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C')
      expect(hash).to match('pbkdf2,oracle12c')
    end
  end

  describe 'identify_phpass_P' do
    it 'returns phpass' do
      hash = described_class.identify_hash('$P$984478476IagS59wHZvyQMArzfx58u.')
      expect(hash).to match('phpass')
    end
  end

  describe 'identify_phpass_H' do
    it 'returns phpass' do
      hash = described_class.identify_hash('$H$984478476IagS59wHZvyQMArzfx58u.')
      expect(hash).to match('phpass')
    end
  end

  describe 'identify_PBKDF2-HMAC-SHA512' do
    it 'returns PBKDF2-HMAC-SHA512' do
      hash = described_class.identify_hash('$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222')
      expect(hash).to match('PBKDF2-HMAC-SHA512')
    end
  end

  describe 'identify_PBKDF2-HMAC-SHA1' do
    it 'returns PBKDF2-HMAC-SHA1' do
      hash = described_class.identify_hash('{PKCS5S2}8WEZjkCbLWysbcbZ5PRgMbdJgJOhkzRT3y1jxOqke2z1Zr79q8ypugFQEYaMoIZt')
      expect(hash).to match('PBKDF2-HMAC-SHA1')
    end
  end

  describe 'identify_mediawiki' do
    it 'returns mediawiki' do
      hash = described_class.identify_hash('$B$113$de2874e33da25313d808d2a8cbf31485')
      expect(hash).to match('mediawiki')
    end
  end

  describe 'identify_android_sha1' do
    it 'returns android-sha1' do
      hash = described_class.identify_hash('EA8457DE97836C955082AE77DBE2CD86A4E8BC0E:4aafc54dc502e88b')
      expect(hash).to match('android-sha1')
    end
  end

  describe 'identify_hmac_md5' do
    it 'returns hmac-md5' do
      hash = described_class.identify_hash('<771138767145@127.0.0.1>#332b463fcf3baac718c63860a7093df4')
      expect(hash).to match('hmac-md5')
    end
  end

  describe 'identify_f5_secure_value' do
    it 'returns F5-Secure-Vault' do
      hash = described_class.identify_hash('$M$iE$cIdy72xi7Xbk3kazSrpdfscd+oD1pdsXJbwhvhMPiss4Iw0RKIJQS/CuSReZl/+kseKpPCNpBWNWOOaBCwlQ0v4sl7ZUkxCymh5pfFNAjhc=')
      expect(hash).to match('F5-Secure-Vault')
    end
  end

  describe 'identify_mscash' do
    it 'returns mscash' do
      hash = described_class.identify_hash('M$3060147285011#4dd8965d1d476fa0d026722989a6b772:::')
      expect(hash).to match('mscash')
    end
  end

  describe 'identify_mscash2' do
    it 'returns mscash2' do
      hash = described_class.identify_hash('$DCC2$10240#username#5f9d79a71fa6d92c31cf16d6eaa23435:::')
      expect(hash).to match('mscash2')
    end
  end

  describe 'identify_netntlm' do
    it 'returns netntlm' do
      hash = described_class.identify_hash('u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c')
      expect(hash).to match('netntlm')
    end
  end

  describe 'identify_netntlmv2' do
    it 'returns netntlmv2' do
      hash = described_class.identify_hash('admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030')
      expect(hash).to match('netntlmv2')
    end
  end

  describe 'identify_krb5tgs_hashcat_format' do
    it 'returns krb5tgs' do
      hash = described_class.identify_hash('$krb5tgs$23$*svc_test$MSFLAB.LOCAL$MSSQLSvc/sql01.msflab.local:1433*$cd5188391bf0e980a2cc48fddfcdb6c9$838309d0fe47fe1452faa663a378b37b5b69a170ee564ef4197f7f7ac918923e39dc0fe17b3beb9a963af47929d506d9d798fefb6038fe6447401cf23212a27aca5f05b8248aed48190d4b6b41405e796a960cc8c02bacb5c5e9869226e039f2581d98cd4d0defe15fd131d48a38ce95d69e28d8ae5f5fcfd371bdab8a68cd044c71a1b1cd46a0fb35eea7043bc7c3703186a9a0dcf6e8b688fdde20603de5daa7d428cf2923c0ba59a12c855ba396e080055e6d340231ba4822db632d12ba19eec436815fc28c88d8852601d58217019566c7c601ed37bb96920bbef4bf357b8e73549dbb70a5f4c53609c008e55d093b409572699b86fc8bd8cc395d6ec2de5fb2f64c56b7f6dd85ab89094883df99f3fd24db442b6da46c8998b3a5bd407fcb6fb2b65faded0b37034b54fa398d604c7030f52db4826ba09698a9a56a2f57a93f5299033cdcd641b4678926df5d8730b6b923c663fa2f9f2fa5f225a4108380f2b7bb9d75620478d1b912949a346bf19688877fcdf92231387b4c1d9ae83420abd38215802859c535205f8673125e0a559aa646663f4e41e97e5339be48972cafb501d01d3ec0f13bcc578b431b74eb285084d167d307ef5b5e2a2fa7cae7b221a6f5a0ce6a45883e6ccbdedcec7cfbc1dec3cad4b53d2db01750e087906747f3e5ed6d3e776a8844f578ff2072325d3d8122fd08342a18d5a637275aa1c534a78e9f798eb61dc2ca4a3cab0ea5b20bf67739763298cee85cc51443ba4faaf069593639fd474c69f31a5f6f29eb1ef20692091eb9eed5aa729dc84af1dde99ccbc978f2334fb1906d224101c425e088d98608ea05b7d4dccdee207d5a3e672829f35e3be751e2b395002619a6e0863e41b10efc321f2ae57fed86b5ed90b5a641e6d3488335ea4e8d8bea397ce35fa0113cf05b4c0c38ee0140d4be3bd490b461dc4fb41b4fc2c50bee160d379934f4043fec940f1549aee56543f7ba6c9c309805fe7397374bed469f1e1dabb6cdad02c9f663b17c64e6bb5a248f1389c2032b15e96d46172526329c29acf04ff537049420efc71aba58f29bac5b6a09522aa893d97ca59de9cc6d13789617859c0db170443e943e58ec7604745e475d1b16057aa8975b0b668fffc9a32f8b26452fa4a95129c53f8cf9a0191898dd8694ad9f0e106d7866b3e3116f92c2921e6ed6fc03a12a2aed56d73d6f9eee8eccad27839f55aef53942c2d7efc0e765621ba72d2280c21df512628011a56fc1aae3a6e62dc87cdd0a4c0c5a179b8ae233ce785293e7eca0b76a6418b0cf798be1eaf7a33f220dbdbb5166a529f129582b5a57b01b90c5c7c48b4d7c8e8aac1677704af319bd73816bbfa344cb10f070426746f162a4fc5809a5c37d566c45043b77e53e6cfb703e511ec1e6d14200d9b859fad51fb93b2477b61435ddcbea97ebf7c4b3dacbec3f8158c5c1d317887b7233199d20d7536febb8dd255aab')
      expect(hash).to match('krb5tgs')
    end
  end

  describe 'identify_krb5tgs_john_format' do
    it 'returns krb5tgs' do
      # https://github.com/openwall/john/issues/5944#issuecomment-3772129757
      hash = described_class.identify_hash('$krb5tgs$23$*svc_test$MSFLAB.LOCAL$MSSQLSvc/sql01.msflab.local*$cd5188391bf0e980a2cc48fddfcdb6c9$838309d0fe47fe1452faa663a378b37b5b69a170ee564ef4197f7f7ac918923e39dc0fe17b3beb9a963af47929d506d9d798fefb6038fe6447401cf23212a27aca5f05b8248aed48190d4b6b41405e796a960cc8c02bacb5c5e9869226e039f2581d98cd4d0defe15fd131d48a38ce95d69e28d8ae5f5fcfd371bdab8a68cd044c71a1b1cd46a0fb35eea7043bc7c3703186a9a0dcf6e8b688fdde20603de5daa7d428cf2923c0ba59a12c855ba396e080055e6d340231ba4822db632d12ba19eec436815fc28c88d8852601d58217019566c7c601ed37bb96920bbef4bf357b8e73549dbb70a5f4c53609c008e55d093b409572699b86fc8bd8cc395d6ec2de5fb2f64c56b7f6dd85ab89094883df99f3fd24db442b6da46c8998b3a5bd407fcb6fb2b65faded0b37034b54fa398d604c7030f52db4826ba09698a9a56a2f57a93f5299033cdcd641b4678926df5d8730b6b923c663fa2f9f2fa5f225a4108380f2b7bb9d75620478d1b912949a346bf19688877fcdf92231387b4c1d9ae83420abd38215802859c535205f8673125e0a559aa646663f4e41e97e5339be48972cafb501d01d3ec0f13bcc578b431b74eb285084d167d307ef5b5e2a2fa7cae7b221a6f5a0ce6a45883e6ccbdedcec7cfbc1dec3cad4b53d2db01750e087906747f3e5ed6d3e776a8844f578ff2072325d3d8122fd08342a18d5a637275aa1c534a78e9f798eb61dc2ca4a3cab0ea5b20bf67739763298cee85cc51443ba4faaf069593639fd474c69f31a5f6f29eb1ef20692091eb9eed5aa729dc84af1dde99ccbc978f2334fb1906d224101c425e088d98608ea05b7d4dccdee207d5a3e672829f35e3be751e2b395002619a6e0863e41b10efc321f2ae57fed86b5ed90b5a641e6d3488335ea4e8d8bea397ce35fa0113cf05b4c0c38ee0140d4be3bd490b461dc4fb41b4fc2c50bee160d379934f4043fec940f1549aee56543f7ba6c9c309805fe7397374bed469f1e1dabb6cdad02c9f663b17c64e6bb5a248f1389c2032b15e96d46172526329c29acf04ff537049420efc71aba58f29bac5b6a09522aa893d97ca59de9cc6d13789617859c0db170443e943e58ec7604745e475d1b16057aa8975b0b668fffc9a32f8b26452fa4a95129c53f8cf9a0191898dd8694ad9f0e106d7866b3e3116f92c2921e6ed6fc03a12a2aed56d73d6f9eee8eccad27839f55aef53942c2d7efc0e765621ba72d2280c21df512628011a56fc1aae3a6e62dc87cdd0a4c0c5a179b8ae233ce785293e7eca0b76a6418b0cf798be1eaf7a33f220dbdbb5166a529f129582b5a57b01b90c5c7c48b4d7c8e8aac1677704af319bd73816bbfa344cb10f070426746f162a4fc5809a5c37d566c45043b77e53e6cfb703e511ec1e6d14200d9b859fad51fb93b2477b61435ddcbea97ebf7c4b3dacbec3f8158c5c1d317887b7233199d20d7536febb8dd255aab')
      expect(hash).to match('krb5tgs')
    end
  end

  describe 'identify_krb5tgs-aes128' do
    it 'returns krb5tgs-aes128' do
      hash = described_class.identify_hash('$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e')
      expect(hash).to match('krb5tgs-aes128')
    end
  end

  describe 'identify_krb5tgs-aes256' do
    it 'returns krb5tgs-aes256' do
      hash = described_class.identify_hash('$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0')
      expect(hash).to match('krb5tgs-aes256')
    end
  end

  describe 'identify_krb5asrep' do
    it 'returns krb5asrep' do
      hash = described_class.identify_hash('$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac')
      expect(hash).to match('krb5asrep')
    end
  end

  describe 'identify_timeroast' do
    it 'returns timeroast' do
      hash = described_class.identify_hash('$sntp-ms$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380')
      expect(hash).to match('timeroast')
    end
  end

  describe 'identify_vnc' do
    it 'returns vnc' do
      hash = described_class.identify_hash('*00112233445566778899aabbccddeeff*6feb3cb1f07b66151656b5832341f223')
      expect(hash).to match('vnc')
    end
    it 'returns vnc on uppercase' do
      hash = described_class.identify_hash('*00112233445566778899aabbccddeeff*6feb3cb1f07b66151656b5832341f223'.upcase)
      expect(hash).to match('vnc')
    end
    it 'returns vnc on no leading star' do
      hash = described_class.identify_hash('00112233445566778899aabbccddeeff*6feb3cb1f07b66151656b5832341f223')
      expect(hash).to match('vnc')
    end
  end

  describe 'identify_pbkdf2-sha256' do
    it 'returns pbkdf2-sha256' do
      hash = described_class.identify_hash('$pbkdf2-sha256$260000$Q1hzYjU5dFNMWm05QUJCTg$s.vmjGlIV0ZKV1Sp3dTdrcn/i9CTqxPZ0klve4HreeU')
      expect(hash).to match('pbkdf2-sha256')
    end
  end

  describe 'identify_empty_string' do
    it 'returns empty string' do
      hash = described_class.identify_hash('')
      expect(hash).to match('')
    end
  end

  describe 'identify_nil' do
    it 'returns empty string' do
      hash = described_class.identify_hash(nil)
      expect(hash).to match('')
    end
  end

  describe 'identify_shadow_line' do
    it 'returns empty string' do
      hash = described_class.identify_hash('root:$1$TDQFedzX$.kv51AjM.FInu0lrH1dY30:15045:0:99999:7:::')
      expect(hash).to match('')
    end
  end

  describe 'identify_un_pass' do
    it 'returns empty string' do
      hash = described_class.identify_hash('root:$1$TDQFedzX$.kv51AjM.FInu0lrH1dY30')
      expect(hash).to match('')
    end
  end

  describe 'identify_ascii_as_nothing' do
    it 'returns empty string' do
      hash = described_class.identify_hash('This is just some words')
      expect(hash).to match('')
    end
  end
end
