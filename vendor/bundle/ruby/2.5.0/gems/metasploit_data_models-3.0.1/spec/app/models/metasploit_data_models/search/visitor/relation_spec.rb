RSpec.describe MetasploitDataModels::Search::Visitor::Relation, type: :model do
  subject(:visitor) do
    described_class.new(
        :query => query
    )
  end

  let(:formatted) do
    # needs to be a valid operation so that query is valid
    "name:\"#{value}\""
  end

  let(:klass) {
    Mdm::Host
  }

  let(:query) do
    Metasploit::Model::Search::Query.new(
        :formatted => formatted,
        :klass => klass
    )
  end

  let(:value) {
    FactoryBot.generate :mdm_host_name
  }

  it_should_behave_like 'Metasploit::Concern.run'

  context 'validations' do
    context 'query' do
      it { is_expected.to validate_presence_of(:query) }

      context 'valid' do
        let(:error) do
          I18n.translate('errors.messages.invalid')
        end

        let(:errors) do
          visitor.errors[:query]
        end

        context 'with query' do
          let(:query) do
            double('Query')
          end

          before(:example) do
            allow(query).to receive(:valid?).and_return(query)

            visitor.valid?
          end

          context 'with valid' do
            let(:valid) do
              true
            end

            it 'should not record error' do
              expect(errors).not_to include(error)
            end
          end

          context 'without valid' do
            let(:valid) do
              false
            end

            it 'should record error' do
              expect(errors).not_to include(error)
            end
          end
        end

        context 'without query' do
          let(:query) do
            nil
          end

          it 'should not record error' do
            expect(errors).not_to include(error)
          end
        end
      end
    end
  end

  context '#visit' do
    subject(:visit) do
      visitor.visit
    end

    context 'MetasploitDataModels::Search::Visitor::Includes' do
      subject(:includes_visitor) do
        visitor.visitor_by_relation_method[:includes]
      end

      it 'should visit Metasploit::Model::Search::Query#tree' do
        expect(includes_visitor).to receive(:visit).with(query.tree)

        visit
      end

      it 'should pass visited to ActiveRecord::Relation#includes' do
        visited = double('Visited')
        allow(includes_visitor).to receive(:visit).with(query.tree).and_return(visited)

        expect_any_instance_of(ActiveRecord::Relation).to receive(:includes).with(visited).and_return(query.klass.all)

        visit
      end
    end

    context 'MetasploitDataModels::Search::Visitor::Joins' do
      subject(:joins_visitor) do
        visitor.visitor_by_relation_method[:joins]
      end

      it 'should visit Metasploit::Model::Search::Query#tree' do
        expect(joins_visitor).to receive(:visit).with(query.tree)

        visit
      end

      it 'should pass visited to ActiveRecord::Relation#joins' do
        visited = double('Visited')
        allow(joins_visitor).to receive(:visit).with(query.tree).and_return(visited)

        expect_any_instance_of(ActiveRecord::Relation).to receive(:joins).with(visited).and_return(query.klass.all)

        visit
      end
    end

    context 'MetasploitDataModels::Search::Visitor::Where' do
      subject(:where_visitor) do
        visitor.visitor_by_relation_method[:where]
      end

      it 'should visit Metasploit::Model::Search::Query#tree' do
        expect(where_visitor).to receive(:visit).with(query.tree)

        visit
      end

      it 'should pass visited to ActiveRecord::Relation#includes' do
        visited = double('Visited')
        allow(where_visitor).to receive(:visit).with(query.tree).and_return(visited)

        expect_any_instance_of(ActiveRecord::Relation).to receive(:where).with(visited).and_return(query.klass.all)

        visit
      end
    end

    context 'matching record' do
      context 'Metasploit::Model::Search::Query#klass' do
        context 'with Mdm::Service' do
          include_context 'Rex::Text'

          #
          # lets
          #

          let(:klass) {
            Mdm::Service
          }

          #
          # Don't use factories to prevent prefix aliasing when sequences go from 1 to 10 or 10 to 100
          #

          let(:non_matching_host) {
            FactoryBot.create(
                :mdm_host,
                address: non_matching_host_address,
                name: non_matching_host_name,
                os_flavor: non_matching_host_os_flavor,
                os_name: non_matching_host_os_name,
                os_sp: non_matching_host_os_sp
            ).tap { |host|
              FactoryBot.create(
                  :mdm_host_tag,
                  host: host,
                  tag: non_matching_tag
              )
            }
          }

          let(:non_matching_host_address) {
            '5.6.7.8'
          }

          let(:non_matching_host_name) {
            'mdm_host_name_b'
          }

          let(:non_matching_host_os_flavor) {
            'mdm_host_os_flavor_b'
          }

          let(:non_matching_host_os_name) {
            'mdm_host_os_name_b'
          }

          let(:non_matching_host_os_sp) {
            'mdm_host_os_sp_b'
          }

          let(:non_matching_info) {
            'mdm_service_info_c'
          }

          let(:non_matching_name) {
            'mdm_service_name_c'
          }

          let(:non_matching_port) {
            3
          }

          let(:non_matching_proto) {
            'udp'
          }

          let(:non_matching_tag) {
            FactoryBot.create(
                :mdm_tag,
                desc: non_matching_tag_desc,
                name: non_matching_tag_name
            )
          }

          let(:non_matching_tag_desc) {
            'Mdm::Tag#description b'
          }

          let(:non_matching_tag_name) {
            'mdm_tag_name.b'
          }

          #
          # let!s
          #

          let!(:non_matching_record) {
            FactoryBot.create(
                :mdm_service,
                host: non_matching_host,
                info: non_matching_info,
                name: non_matching_name,
                port: non_matching_port,
                proto: non_matching_proto
            )
          }

          context 'with port' do
            #
            # lets
            #

            let(:matching_ports) {
              [
                  1,
                  2
              ]
            }

            let(:matching_records) {
              matching_record_by_port.values
            }

            #
            # let!s
            #

            let!(:matching_record_by_port) {
              matching_ports.each_with_object({}) { |matching_port, matching_record_by_port|
                matching_record_by_port[matching_port] = FactoryBot.create(
                    :mdm_service,
                    port: matching_port
                )
              }
            }

            context 'with single port number' do
              let(:formatted) {
                "port:#{matching_port}"
              }

              let(:matching_port) {
                matching_ports.sample
              }

              let(:matching_record) {
                matching_record_by_port[matching_port]
              }

              it 'should find only record with that port number' do
                expect(visit).to match_array([matching_record])
              end
            end

            context 'with port range' do
              let(:formatted) {
                "port:#{matching_ports.min}-#{matching_ports.max}"
              }

              it 'should find all records with port numbers within the range' do
                expect(visit).to match_array(matching_records)
              end
            end

            context 'with comma separated port numbers' do
              let(:formatted) {
                "port:#{matching_ports.join(',')}"
              }

              it 'should find all records with the port numbers' do
                expect(visit).to match_array(matching_records)
              end
            end

            context 'with overlapping comma separated port number and range' do
              let(:matching_port) {
                matching_ports.sample
              }

              let(:formatted) {
                %Q{port:#{matching_port},#{matching_ports.min}-#{matching_ports.max}}
              }

              it 'should find all records with the matching ports once' do
                expect(visit).to match_array(matching_records)
              end
            end
          end

          context 'with single matching record' do
            #
            # lets
            #

            #
            # Don't use factories to prevent prefix aliasing when sequences go from 1 to 10 or 10 to 100
            #

            let(:matching_host) {
              FactoryBot.create(
                  :mdm_host,
                  address: matching_host_address,
                  name: matching_host_name,
                  os_flavor: matching_host_os_flavor,
                  os_name: matching_host_os_name,
                  os_sp: matching_host_os_sp
              ).tap { |host|
                FactoryBot.create(
                    :mdm_host_tag,
                    host: host,
                    tag: matching_tag
                )
              }
            }

            let(:matching_host_address) {
              '1.2.3.4'
            }

            let(:matching_host_name) {
              'mdm_host_name_a'
            }

            let(:matching_host_os_flavor) {
              'mdm_host_os_flavor_a'
            }

            let(:matching_host_os_name) {
              'mdm_host_os_name_a'
            }

            let(:matching_host_os_sp) {
              'mdm_host_os_sp_a'
            }

            let(:matching_info) {
              'mdm_service_info_a'
            }

            let(:matching_name) {
              'mdm_service_name_a'
            }

            let(:matching_port) {
              1
            }

            let(:matching_proto) {
              'tcp'
            }

            let(:matching_tag) {
              FactoryBot.create(
                  :mdm_tag,
                  desc: matching_tag_desc,
                  name: matching_tag_name
              )
            }

            let(:matching_tag_desc) {
              'Mdm::Tag#description a'
            }

            let(:matching_tag_name) {
              'mdm_tag_name.a'
            }

            #
            # let!s
            #

            let!(:matching_record) {
              FactoryBot.create(
                  :mdm_service,
                  host: matching_host,
                  info: matching_info,
                  name: matching_name,
                  port: matching_port,
                  proto: matching_proto
              )
            }

            context 'with host.address operator' do
              let(:formatted) do
                "host.address:#{formatted_address}"
              end

              context 'with CIDR' do
                let(:formatted_address) {
                  '1.3.4.5/8'
                }

                it 'should find only matching record' do
                  expect(visit).to match_array([matching_record])
                end
              end

              context 'with Range' do
                let(:formatted_address) {
                  '1.1.1.1-5.6.7.7'
                }

                it 'should find only matching record' do
                  expect(visit).to match_array([matching_record])
                end
              end

              context 'with single' do
                let(:formatted_address) {
                  '1.2.3.4'
                }

                it 'should find only matching record' do
                  expect(visit).to match_array([matching_record])
                end
              end
            end

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: :host,
                                  attribute: :name

            context 'with host.os' do
              let(:matching_host_os_flavor) {
                'XP'
              }

              let(:matching_host_os_name) {
                'Microsoft Windows'
              }

              let(:matching_host_os_sp) {
                'SP1'
              }

              context 'with a combination of Mdm::Host#os_name and Mdm:Host#os_sp' do
                let(:formatted) {
                  %Q{host.os:"win xp"}
                }

                it 'finds matching record' do
                  expect(visit).to match_array [matching_record]
                end
              end

              context 'with a combination of Mdm::Host#os_flavor and Mdm::Host#os_sp' do
                let(:formatted) {
                  %Q{host.os:"xp sp1"}
                }

                it 'finds matching record' do
                  expect(visit).to match_array [matching_record]
                end
              end

              context 'with multiple records matching one word' do
                let(:formatted) {
                  %Q{host.os:"win xp"}
                }

                let(:non_matching_host_os_name) {
                  'Microsoft Windows'
                }

                it 'finds only matching record by other words refining search' do
                  expect(visit).to match_array [matching_record]
                end
              end
            end

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: :host,
                                  attribute: :os_flavor

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: :host,
                                  attribute: :os_name

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: :host,
                                  attribute: :os_sp

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: {
                                      host: :tags
                                  },
                                  attribute: :desc

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  association: {
                                      host: :tags
                                  },
                                  attribute: :name

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  attribute: :info

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  attribute: :name

            it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                  attribute: :proto

            context 'with all operators' do
              let(:formatted) {
                %Q{
                  host.address:1.3.4.5/8
                  host.address:1.1.1.1-5.6.7.7
                  host.address:1.2.3.4
                  host.name:#{matching_host_name}
                  host.os:"#{matching_host_os_name} #{matching_host_os_flavor} #{matching_host_os_sp}"
                  host.os_flavor:#{matching_host_os_flavor}
                  host.os_name:#{matching_host_os_name}
                  host.os_sp:#{matching_host_os_sp}
                  host.tags.desc:"#{matching_tag_desc}"
                  host.tags.name:#{matching_tag_name}
                  name:#{matching_name}
                  port:#{matching_port}
                  proto:#{matching_proto}
                }
              }

              it 'finds only matching record' do
                expect(visit).to match_array([matching_record])
              end
            end
          end
        end

        context 'with Mdm::Host' do
          #
          # lets
          #
          # Don't use factories to prevent prefix aliasing when sequences go from 1 to 10 or 10 to 100
          #

          let(:matching_record_address) {
            '1.2.3.4'
          }

          let(:matching_record_os_flavor) {
            'mdm_host_os_flavor_a'
          }

          let(:matching_record_os_name) {
            'mdm_host_os_name_a'
          }

          let(:matching_record_os_sp) {
            'mdm_host_os_sp_a'
          }

          let(:matching_record_name) {
            'mdm_host_name_a'
          }

          let(:matching_service_name) {
            'mdm_service_name_a'
          }

          let(:non_matching_record_address) {
            '5.6.7.8'
          }

          let(:non_matching_record_os_flavor) {
            'mdm_host_os_flavor_b'
          }

          let(:non_matching_record_os_name) {
            'mdm_host_os_name_b'
          }

          let(:non_matching_record_os_sp) {
            'mdm_host_os_sp_b'
          }

          let(:non_matching_record_name) {
            'mdm_host_name_b'
          }

          let(:non_matching_service_name) {
            'mdm_service_name_b'
          }

          #
          # let!s
          #

          let!(:matching_record) do
            FactoryBot.build(
                :mdm_host,
                address: matching_record_address,
                name: matching_record_name,
                os_flavor: matching_record_os_flavor,
                os_name: matching_record_os_name,
                os_sp: matching_record_os_sp
            )
          end

          let!(:matching_service) do
            FactoryBot.create(
                :mdm_service,
                host: matching_record,
                name: matching_service_name
            )
          end

          let!(:non_matching_record) do
            FactoryBot.build(
                :mdm_host,
                address: non_matching_record_address,
                name: non_matching_record_name,
                os_flavor: non_matching_record_os_flavor,
                os_name: non_matching_record_os_name,
                os_sp: non_matching_record_os_sp
            )
          end

          let!(:non_matching_service) do
            FactoryBot.create(
                :mdm_service,
                host: non_matching_record,
                name: non_matching_service_name
            )
          end

          context 'with address operator' do
            let(:formatted) do
              "address:#{formatted_address}"
            end

            context 'with CIDR' do
              let(:formatted_address) {
                "'1.3.4.5/8'"
              }

              it 'should find only matching record' do
                expect(visit).to match_array([matching_record])
              end
            end

            context 'with Range' do
              let(:formatted_address) {
                '1.1.1.1-5.6.7.7'
              }

              it 'should find only matching record' do
                expect(visit).to match_array([matching_record])
              end
            end

            context 'with single' do
              let(:formatted_address) {
                '1.2.3.4'
              }

              it 'should find only matching record' do
                expect(visit).to match_array([matching_record])
              end
            end
          end

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                :attribute => :name

          context 'with os' do
            let(:matching_record_os_flavor) {
              'XP'
            }

            let(:matching_record_os_name) {
              'Microsoft Windows'
            }

            let(:matching_record_os_sp) {
              'SP1'
            }

            context 'with a combination of Mdm::Host#os_name and Mdm:Host#os_sp' do
              let(:formatted) {
                %Q{os:"win xp"}
              }

              it 'finds matching record' do
                expect(visit).to match_array [matching_record]
              end
            end

            context 'with a combination of Mdm::Host#os_flavor and Mdm::Host#os_sp' do
              let(:formatted) {
                %Q{os:"xp sp1"}
              }

              it 'finds matching record' do
                expect(visit).to match_array [matching_record]
              end
            end

            context 'with multiple records matching one word' do
              let(:formatted) {
                %Q{os:"win xp"}
              }

              let(:non_matching_record_os_name) {
                'Microsoft Windows'
              }

              it 'finds only matching record by other words refining search' do
                expect(visit).to match_array [matching_record]
              end
            end
          end

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                :attribute => :os_flavor

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                :attribute => :os_name

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                :attribute => :os_sp

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                association: :services,
                                attribute: :name

          context 'with all operators' do
            let(:formatted) {
              %Q{
              address:1.3.4.5/8
              address:1.1.1.1-5.6.7.7
              address:1.2.3.4
              name:"#{matching_record_name}"
              os:"#{matching_record_os_name} #{matching_record_os_flavor} #{matching_record_os_sp}"
              os_flavor:"#{matching_record_os_flavor}"
              os_name:"#{matching_record_os_name}"
              os_sp:"#{matching_record_os_sp}"
              services.name:"#{matching_service_name}"
            }
            }

            it 'should find only matching record' do
              if visit.to_a != [matching_record]
                true
              end

              expect(visit).to match_array([matching_record])
            end
          end
        end

        context 'with Mdm::Tag' do
          #
          # lets
          #

          let(:klass) {
            Mdm::Tag
          }

          let(:matching_desc) {
            'This is a description'
          }

          let(:matching_name) {
            'matching.tag'
          }

          let(:non_matching_desc) {
            'This could be a description'
          }

          let(:non_matching_name) {
            'tag.does.not.match'
          }

          #
          # let!s
          #

          let!(:matching_record) {
            FactoryBot.create(
                :mdm_tag,
                desc: matching_desc,
                name: matching_name
            )
          }

          let!(:non_matching_record) {
            FactoryBot.create(
                :mdm_tag,
                desc: non_matching_desc,
                name: non_matching_name
            )
          }

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                attribute: :desc

          it_should_behave_like 'MetasploitDataModels::Search::Visitor::Relation#visit matching record',
                                attribute: :name

          context 'with all operators' do
            let(:formatted) {
              %Q{desc:"#{matching_desc}" name:"#{matching_name}"}
            }

            it 'should find only matching record' do
              expect(visit).to match_array([matching_record])
            end
          end
        end
      end
    end
  end

  context '#visitor_by_relation_method' do
    subject(:visitor_by_relation_method) do
      visitor.visitor_by_relation_method
    end

    context 'joins' do
      subject(:joins) {
        visitor_by_relation_method[:joins]
      }

      it { is_expected.to be_a MetasploitDataModels::Search::Visitor::Joins }
    end

    context 'includes' do
      subject(:includes) {
        visitor_by_relation_method[:includes]
      }

      it { is_expected.to be_a MetasploitDataModels::Search::Visitor::Includes }
    end

    context 'where' do
      subject(:where) {
        visitor_by_relation_method[:where]
      }

      it { is_expected.to be_a MetasploitDataModels::Search::Visitor::Where }
    end
  end

  context 'visitor_class_by_relation_method' do
    subject(:visitor_class_by_relation_method) do
      described_class.visitor_class_by_relation_method
    end

    context 'joins' do
      subject(:joins) {
        visitor_class_by_relation_method[:joins]
      }

      it { is_expected.to eq(MetasploitDataModels::Search::Visitor::Joins) }
    end

    context 'includes' do
      subject(:includes) {
        visitor_class_by_relation_method[:includes]
      }

      it { is_expected.to eq(MetasploitDataModels::Search::Visitor::Includes) }
    end

    context 'where' do
      subject(:where) {
        visitor_class_by_relation_method[:where]
      }

      it { is_expected.to eq(MetasploitDataModels::Search::Visitor::Where) }
    end
  end
end
