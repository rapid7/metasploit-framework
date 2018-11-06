# encoding: UTF-8

require 'spec_helper'

describe ArelHelpers::Aliases do
  describe "#aliased_as" do
    it "yields an alias when passed a block" do
      Post.aliased_as('foo') do |foo_alias|
        expect(foo_alias).to be_a(Arel::Nodes::TableAlias)
        expect(foo_alias.name).to eq('foo')
      end
    end

    it "is capable of yielding multiple aliases" do
      Post.aliased_as('foo', 'bar') do |foo_alias, bar_alias|
        expect(foo_alias).to be_a(Arel::Nodes::TableAlias)
        expect(foo_alias.name).to eq('foo')

        expect(bar_alias).to be_a(Arel::Nodes::TableAlias)
        expect(bar_alias.name).to eq('bar')
      end
    end

    it "returns an alias when not passed a block" do
      aliases = Post.aliased_as('foo')
      expect(aliases.size).to eq(1)
      expect(aliases[0]).to be_a(Arel::Nodes::TableAlias)
      expect(aliases[0].name).to eq('foo')
    end

    it "is capable of returning multiple aliases" do
      aliases = Post.aliased_as('foo', 'bar')
      expect(aliases.size).to eq(2)

      expect(aliases[0]).to be_a(Arel::Nodes::TableAlias)
      expect(aliases[0].name).to eq('foo')

      expect(aliases[1]).to be_a(Arel::Nodes::TableAlias)
      expect(aliases[1].name).to eq('bar')
    end
  end
end
