require 'spec_helper'
require 'tempfile'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Db::Klist do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject do
    described_class = self.described_class
    instance = Class.new do
      include Msf::Ui::Console::CommandDispatcher
      include Msf::Ui::Console::CommandDispatcher::Common
      include Msf::Ui::Console::CommandDispatcher::Db::Common
      include described_class
    end.new(driver)
    instance
  end

  def kerberos_ticket_storage
    Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite.new(framework: framework)
  end

  # Replace table entry ids with `[id]` for matching simplicity
  # Also corrects spacing between columns to remove variation from different length ids
  def table_without_ids(table)
    output = table.dup
    output.gsub!(/^--\s+----/, '--    ----')
    output.gsub!(/^id\s+host/, 'id    host')
    output.gsub!(/^\d+\s+/, '[id]  ')
  end

  describe '#cmd_klist' do
    before(:each) do
      kerberos_ticket_storage.delete_tickets
    end

    context 'when the -h option is provided' do
      it 'should show a help message' do
        subject.cmd_klist '-h'
        expect(@output.join("\n")).to match_table <<~TABLE
          List Kerberos tickets in the database
          Usage: klist [options] [hosts]

          OPTIONS:

              -a, --activate    Activates *all* matching kerberos entries
              -A, --deactivate  Deactivates *all* matching kerberos entries
              -d, --delete      Delete *all* matching kerberos entries
              -h, --help        Help banner
              -i, --index       Kerberos entry ID(s) to search for, e.g. `-i 1` or `-i 1,2,3` or `-i 1 -i 2 -i 3`
              -v, --verbose     Verbose output

        TABLE
      end
    end

    context 'when there are no tickets' do
      context 'when no options are provided' do
        it 'should show no tickets' do
          subject.cmd_klist
          expect(@output.join("\n")).to match_table <<~TABLE
            Kerberos Cache
            ==============
            No tickets
          TABLE
        end
      end

      context 'when the -v option is provided' do
        it 'should show no tickets' do
          subject.cmd_klist '-v'
          expect(@output.join("\n")).to match_table <<~TABLE
            Kerberos Cache
            ==============
            No tickets
          TABLE
        end
      end

      context 'when the -i option is provided' do
        it 'should show no tickets and missing id warning' do
          subject.cmd_klist '-i', '0' # Can't have an id of 0
          expect(@combined_output.join("\n")).to match_table <<~TABLE
            Not all records with the ids: ["0"] could be found.
            Please ensure all ids specified are available.
            Kerberos Cache
            ==============
            No tickets
          TABLE
        end
      end
    end

    context 'when there are tickets' do
      let(:valid_ccache_base64) do
        <<~EOF
          BQQAAAAAAAEAAAABAAAAD1dJTkRPTUFJTi5MT0NBTAAAAA1BZG1pbmlzdHJh
          dG9yAAAAAQAAAAEAAAAPV0lORE9NQUlOLkxPQ0FMAAAADUFkbWluaXN0cmF0
          b3IAAAABAAAAAgAAAA9XSU5ET01BSU4uTE9DQUwAAAAGa3JidGd0AAAAD1dJ
          TkRPTUFJTi5MT0NBTAASAAAAIDg1NmI4ZGJhNjc2MmFhOTA3OGVmYzEzYTU1
          Mjk0Mzc5Y4TZAWOE2QF2UNwBdlDcAQBQ4AAAAAAAAAAAAAAAAAPRYYIDzTCC
          A8mgAwIBBaERGw9XSU5ET01BSU4uTE9DQUyiJDAioAMCAQGhGzAZGwZrcmJ0
          Z3QbD1dJTkRPTUFJTi5MT0NBTKOCA4cwggODoAMCARKhAwIBAqKCA3UEggNx
          SfCgea/1JxnrCZh8Tx+KB/z5rjaxo8cdmiQ+baACeDjI8hohc975Hjt16643
          pQBhNwyLvqy7O9LJs+Qgt0+3nRLYuHE4Oal2auffQkBJCwf5NyYenRLYvfnX
          pnFwUL4r7vzL4rEWjyIfuBdAC3o6NRJaHnakd5p5CWe1gXG5jNo8dIqRId5z
          jtlbcL8Y3IEbuhtvPcnnZ9EIvMZD1oLQuJyf93Lt4sM4AZDMfaOzbC4o50K0
          oc+0cFULIgEqTuULhIj6JD7fcZlSO7PDYD2Z7zJyNMTv5r/5vygmzuFPuGID
          EkKtV/uOmxZwMNYlB+3swzp8vaYZQo6378z9O1J2nA/LTFhuwpoIR+VtY088
          WoQpb9tD9BGOKH0WxDKvj5fl9ll6WY99XrVmZQZwjpP97SatTmSpGmpszCsC
          pq+P/Zay8HwZWjdcR6OEP1Ymoy6Eg1yAIiMk5gRlVpa+wZAmTOXMpIFqkpC5
          vFSu9OUp0qgGbScusZ64I7ylS8Kpy8AT0cBaSUTvDAxQid9+N65u07S5h2qB
          kdP5lbH9QE46k+Z6Gnps4P1wNFccF8ukBWyEormPoN1paZZ96l7KeRtA6kRw
          Nyd8C9p2yOojDI7ksU43ojYT5VS3a0c5odcs0pyAyhxyzR91toRkHJS4B7yl
          cuFtBQ5HcgUXOgVHu4VjL5Ll8dY/QM7Va0nqDt2RtIwPr3/FuaRFuDKlR3zT
          Fqf3H0DDjLD37VRU7tfm5L8nJZ9hzmA/nd7KCg9Em52R287eWcZ2LNWqJEXX
          Lh7dn4aE6Z4Mnt2sIqBCBLxLln+ePGYkO4KoBTTEfeN4xUC/ZfM+wI7qLh9q
          dwRltmarAqBk2nWeGze4tkw46H2qGd6RrbJgjNUwxX/KhyEGdEqKB2aaf8fR
          JI4pJMJ1+pQa6796UDty32xgue8r1/0QfzinnMcQfQVqfGGazwVm7swo8aT1
          BTGmiOx6iHlBoIkQ3HCUlW/9ynDbp2SBRFqD08n+1eQg39dlF+NVfB7RutFE
          s4BEF/UdLr50/0xKrZzZEBuQSb/LWaggCakhPohfBVBrVEuoH9TDhNZrOrna
          KCi0awaZQrvXPMnqvVqBYM3SsZRXOgDrcq/T79qR9cCvmQT2hhsmrh4c15ld
          VpIpmeR2YS/msnk7iVVhPqec/jkVTvpB7/EAAAAA
        EOF
      end

      let(:expired_ccache_base64) do
        <<~EOF
          BQQAAAAAAAEAAAABAAAACkFERjMuTE9DQUwAAAANQWRtaW5pc3RyYXRvcgAA
          AAEAAAABAAAACkFERjMuTE9DQUwAAAANQWRtaW5pc3RyYXRvcgAAAAEAAAAC
          AAAACkFERjMuTE9DQUwAAAAGa3JidGd0AAAACkFERjMuTE9DQUwAEgAAACDO
          fwBYscwSotMS4+yZQ1OMO0AcTa7Vj+/2W/mw+kCzs2OcXvFjnF7xY5zrkWOd
          sHEAUOEAAAAAAAAAAAAAAAAEQmGCBD4wggQ6oAMCAQWhDBsKQURGMy5MT0NB
          TKIfMB2gAwIBAaEWMBQbBmtyYnRndBsKQURGMy5MT0NBTKOCBAIwggP+oAMC
          ARKhAwIBAqKCA/AEggPs5JyYC0QViXJwK8TeX2uNlLyo1vX50A815LGykwJz
          QXnsL4MKwjo+w99V2eB2O0i53rnRJycPHu2MZtkashcPp/XJHLFFqZ2rEB56
          pax51sU5TExk+td5zyT3su9HNJe89ctXfDqFIzmg3LNhvicEJHcF+eg7DVgG
          h2/h2/uHsbpq857XT/w3gq+NK8HIiwbYZLXDSv35qi58xHWm5uTJNBmn9vBS
          V2YMHbFOzU+BhKxR9CaT5pLW0iNedkwbV539lvcAoNfcghKg4SkWU49q+pQJ
          8R+giMvl7PltU9DAAB/tgJL8VK32lLbHQYSHZPO6TnBOgIaxfGR2vX0C6XRa
          OIDu1wioM443Ekswe1MFBxVP5Hu/xWryW6q8nbGBFPL+37q/IB/j4vzuvkpx
          5p/Izx8vwmJE3IyrvqNlxC1M1TbqhcpwLeqHRPWjgd+4WuyEqXw/TLycrISF
          TFkgOW00DxUVY4ZD2IoQ1vjwoCngokcK6QXKictANJAinUMsqwVb2kcP3TJg
          bD7EEGbvaDBsRmwMZTgF5ZgmmVs6SIwCAxf4hEf1EvEiMF1UaY1xckfGCnnO
          lOwJZg2PGbqVciKLwdeRw9iK1u9pwmsmDr033/cvfrkFm1ggrA2T/VqQ7Uv/
          5WQpt5/GuGv8WYD7F+CV1zWVr5I3ejbXFk2X7HVlHVW3zx2xaKrNdsk6yOSQ
          cQREhfCQvCjFenH39uSMV36zM6c4Z97oYvcZUpPg6sazpA5KEm86DharyEhV
          mTeGbpVAV7Asfq0ojh6nPQem6a6Hrim4fSqEH4rsMuwOPCDfritUBDCALB2b
          hRrT54+290jFu0cRDE4FM34rAm4XXXxFF3wuHWJEeNWsvtnd/ot5ocmEenCB
          fM695wfVVyDJq/VA90C7RNvvFG/rbTDTDmkZc2H5xCxRVn3HaSC6d4S/81KR
          MnwEhjhhWHjC7l1an3gRamL33eDT2/y67huwDxoaaQMaI0u47hHaB4IxZBS2
          8T4OusfJrwLgoWVp3DKmkTZD2vFWv0W0mtrdYHFOvgNNd3vU771Cc8AXMnW4
          G5Ne3igy7vfI4GnIFeAz088E7sxDwCeXfXB1+Y3CNPGMn0DkUzIWd9nxjDXu
          3bdN7shsEtntT+JEOgQAChqZ7ay5DigaC3P503NkBskOnFUHz1xLTvBKFicB
          akAIyxtxqa7C2D8DM5v0i3pCcVwbMqcKXk46AUTmmcCMrra6WiXqHRZ/s/UZ
          jWwnrBd80k8d1MFVotad/XPKxDmNLeTw5KiqJx4hTEWsvrXw0P5UMu3reeIk
          WnABsFKVaMithek8a9aRyBsuwSSgkAIJHXy8tHsAAAAA
        EOF
      end

      # @param [String] data Base64 encoded
      def as_ccache(data)
        Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(Base64.decode64(data))
      end

      let(:valid_ccache) do
        kerberos_ticket_storage.store_ccache(as_ccache(valid_ccache_base64), host: '192.0.2.2')
      end

      let(:valid_ccache_id) do
        valid_ccache[:loot].id
      end

      let(:valid_ccache_path) do
        kerberos_ticket_storage.tickets(id: valid_ccache_id).first.path
      end

      let(:expired_ccache) do
        kerberos_ticket_storage.store_ccache(as_ccache(expired_ccache_base64), host: '192.0.2.24')
      end

      let(:expired_ccache_id) do
        expired_ccache[:loot].id
      end

      let(:expired_ccache_path) do
        kerberos_ticket_storage.tickets(id: expired_ccache_id).first.path
      end


      let(:create_tickets) do
        [valid_ccache, expired_ccache]
      end

      before(:each) do
        Timecop.freeze(Time.parse('Dec 18, 2022 12:33:40.000000000 GMT'))
        create_tickets
      end

      after do
        Timecop.return
      end

      context 'when no options are provided' do
        it 'should show tickets' do
          subject.cmd_klist
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
          TABLE
        end
      end

      context 'when a host address is specified' do
        it 'should show the matching host addresses' do
          subject.cmd_klist '192.0.2.2'
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host       principal                      sname                                   enctype  issued                     status  path
            --    ----       ---------                      -----                                   -------  ------                     ------  ----
            [id]  192.0.2.2  Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active  #{valid_ccache_path}
          TABLE
        end
      end

      context 'when the -v option is provided' do
        it 'should show tickets' do
          expected_cipher = <<~CIPHER.lines(chomp: true).join('')
            SfCgea/1JxnrCZh8Tx+KB/z5rjaxo8cdmiQ+baACeDjI8hohc975Hjt16643pQBhNwyLvqy7
            O9LJs+Qgt0+3nRLYuHE4Oal2auffQkBJCwf5NyYenRLYvfnXpnFwUL4r7vzL4rEWjyIfuBdA
            C3o6NRJaHnakd5p5CWe1gXG5jNo8dIqRId5zjtlbcL8Y3IEbuhtvPcnnZ9EIvMZD1oLQuJyf
            93Lt4sM4AZDMfaOzbC4o50K0oc+0cFULIgEqTuULhIj6JD7fcZlSO7PDYD2Z7zJyNMTv5r/5
            vygmzuFPuGIDEkKtV/uOmxZwMNYlB+3swzp8vaYZQo6378z9O1J2nA/LTFhuwpoIR+VtY088
            WoQpb9tD9BGOKH0WxDKvj5fl9ll6WY99XrVmZQZwjpP97SatTmSpGmpszCsCpq+P/Zay8HwZ
            WjdcR6OEP1Ymoy6Eg1yAIiMk5gRlVpa+wZAmTOXMpIFqkpC5vFSu9OUp0qgGbScusZ64I7yl
            S8Kpy8AT0cBaSUTvDAxQid9+N65u07S5h2qBkdP5lbH9QE46k+Z6Gnps4P1wNFccF8ukBWyE
            ormPoN1paZZ96l7KeRtA6kRwNyd8C9p2yOojDI7ksU43ojYT5VS3a0c5odcs0pyAyhxyzR91
            toRkHJS4B7ylcuFtBQ5HcgUXOgVHu4VjL5Ll8dY/QM7Va0nqDt2RtIwPr3/FuaRFuDKlR3zT
            Fqf3H0DDjLD37VRU7tfm5L8nJZ9hzmA/nd7KCg9Em52R287eWcZ2LNWqJEXXLh7dn4aE6Z4M
            nt2sIqBCBLxLln+ePGYkO4KoBTTEfeN4xUC/ZfM+wI7qLh9qdwRltmarAqBk2nWeGze4tkw4
            6H2qGd6RrbJgjNUwxX/KhyEGdEqKB2aaf8fRJI4pJMJ1+pQa6796UDty32xgue8r1/0Qfzin
            nMcQfQVqfGGazwVm7swo8aT1BTGmiOx6iHlBoIkQ3HCUlW/9ynDbp2SBRFqD08n+1eQg39dl
            F+NVfB7RutFEs4BEF/UdLr50/0xKrZzZEBuQSb/LWaggCakhPohfBVBrVEuoH9TDhNZrOrna
            KCi0awaZQrvXPMnqvVqBYM3SsZRXOgDrcq/T79qR9cCvmQT2hhsmrh4c15ldVpIpmeR2YS/m
            snk7iVVhPqec/jkVTvpB7/E=
          CIPHER

          subject.cmd_klist '-v', '192.0.2.2'
          expect(@output.join("\n")).to match_table <<~TABLE
            Kerberos Cache
            ==============
            Cache[0]:
              Primary Principal: Administrator@WINDOMAIN.LOCAL
              Ccache version: 4

              Creds: 1
                Credential[0]:
                  Server: krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL
                  Client: Administrator@WINDOMAIN.LOCAL
                  Ticket etype: 18 (AES256)
                  Key: 3835366238646261363736326161393037386566633133613535323934333739
                  Subkey: false
                  Ticket Length: 977
                  Ticket Flags: 0x50e00000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT)
                  Addresses: 0
                  Authdatas: 0
                  Times:
                    Auth time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
                    Start time: #{Time.parse('2022-11-28 15:51:29 +0000').localtime}
                    End time: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
                    Renew Till: #{Time.parse('2032-11-25 15:51:29 +0000').localtime}
                  Ticket:
                    Ticket Version Number: 5
                    Realm: WINDOMAIN.LOCAL
                    Server Name: krbtgt/WINDOMAIN.LOCAL
                    Encrypted Ticket Part:
                      Ticket etype: 18 (AES256)
                      Key Version Number: 2
                      Cipher:
                        #{expected_cipher}
          TABLE
        end
      end

      context 'when the -d flag is used' do
        it 'should show the deleted tickets' do
          # Store the paths first before they are deleted
          old_valid_ccache_path = valid_ccache_path
          old_expired_ccache_path = expired_ccache_path
          subject.cmd_klist '-d'
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{old_valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{old_expired_ccache_path}
            Deleted 2 entries
          TABLE
          expect(kerberos_ticket_storage.tickets.length).to eq(0)
        end
      end

      context 'when the -i option is provided with a single id' do
        it 'should show a single ticket' do
          subject.cmd_klist '-i', valid_ccache_id.to_s
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host       principal                      sname                                   enctype  issued                     status  path
            --    ----       ---------                      -----                                   -------  ------                     ------  ----
            [id]  192.0.2.2  Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active  #{valid_ccache_path}
          TABLE
        end
      end

      context 'when the -i option is provided twice with different ids' do
        it 'should show both tickets' do
          subject.cmd_klist '-i', valid_ccache_id.to_s, '-i', expired_ccache_id.to_s
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
          TABLE
        end
      end

      context 'when the -i option is provided with 2 valid ids (comma separated)' do
        it 'should show both tickets' do
          subject.cmd_klist '-i', "#{valid_ccache_id},#{expired_ccache_id}"
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
          TABLE
        end
      end

      context 'when the -i option is provided with 2 valid ids (quoted and space separated)' do
        it 'should show both tickets' do
          subject.cmd_klist '-i', "#{valid_ccache_id} #{expired_ccache_id}"
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
          TABLE
        end
      end

      context 'when the -i option is provided with 2 valid ids (quoted and comma + space separated)' do
        it 'should show both tickets' do
          subject.cmd_klist '-i', "#{valid_ccache_id}, #{expired_ccache_id}"
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
          TABLE
        end
      end

      context 'when the -i option is provided with 1 valid and 1 invalid id' do
        it 'should show both tickets' do
          subject.cmd_klist '-i', valid_ccache_id.to_s, '-i', '0' # Can't have an id of 0
          expect(@combined_output.join("\n")).to match_table <<~TABLE
            Not all records with the ids: ["#{valid_ccache_id}", "0"] could be found.
            Please ensure all ids specified are available.
            Kerberos Cache
            ==============
            No tickets
          TABLE
        end
      end

      context 'when the -i option is provided with a loot id that is not a ccache' do
        let(:loot) do
          framework.db.report_loot(type: 'not a ccache', name: 'fake_loot', path: 'fake_path')
        end

        before do
          loot
        end

        after do
          framework.db.delete_loot(ids: [loot.id])
        end

        # This behaviour is inconsistent with providing an id that doesn't exist in the loot table at all
        it 'will not show any tickets' do
          subject.cmd_klist '-i', loot.id.to_s
          expect(@output.join("\n")).to match_table <<~TABLE
            Kerberos Cache
            ==============
            No tickets
          TABLE
        end
      end

      context 'when the -A option is provided the tickets will be deactivated' do
        it 'will show the deactivated tickets' do
          subject.cmd_klist '-A'
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host        principal                      sname                                   enctype  issued                     status       path
            --    ----        ---------                      -----                                   -------  ------                     ------       ----
            [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  inactive     #{valid_ccache_path}
            [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
            Deactivated 2 entries
          TABLE
        end
      end

      context 'when there is a deactivated ticket' do
        before do
          subject.cmd_klist '-A'
          reset_logging!
        end

        context 'when the -a option is provided the tickets will be activated' do
          it 'will show the activated tickets' do
            subject.cmd_klist '-a'
            expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
              Kerberos Cache
              ==============
              id    host        principal                      sname                                   enctype  issued                     status       path
              --    ----        ---------                      -----                                   -------  ------                     ------       ----
              [id]  192.0.2.2   Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active       #{valid_ccache_path}
              [id]  192.0.2.24  Administrator@ADF3.LOCAL       krbtgt/ADF3.LOCAL@ADF3.LOCAL            AES256   #{Time.parse('2022-12-16 12:05:05 +0000').localtime}  >>expired<<  #{expired_ccache_path}
              Activated 2 entries
            TABLE
          end
        end
      end

      context 'when an index is provided with the delete option' do
        it 'will delete the single entry provided' do
          # Store the paths first before they are deleted
          old_valid_ccache_path = valid_ccache_path
          subject.cmd_klist '-d', '-i', valid_ccache_id.to_s
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host       principal                      sname                                   enctype  issued                     status  path
            --    ----       ---------                      -----                                   -------  ------                     ------  ----
            [id]  192.0.2.2  Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  active  #{old_valid_ccache_path}
            Deleted 1 entry
          TABLE
          expect(kerberos_ticket_storage.tickets.length).to eq(1)
        end
      end

      context 'when an index is provided with the deactivate option' do
        it 'will deactivate the single entry provided' do
          subject.cmd_klist '-A', '-i', valid_ccache_id.to_s
          expect(table_without_ids(@output.join("\n"))).to match_table <<~TABLE
            Kerberos Cache
            ==============
            id    host       principal                      sname                                   enctype  issued                     status    path
            --    ----       ---------                      -----                                   -------  ------                     ------    ----
            [id]  192.0.2.2  Administrator@WINDOMAIN.LOCAL  krbtgt/WINDOMAIN.LOCAL@WINDOMAIN.LOCAL  AES256   #{Time.parse('2022-11-28 15:51:29 +0000').localtime}  inactive  #{valid_ccache_path}
            Deactivated 1 entry
          TABLE
        end
      end
    end
  end
end
