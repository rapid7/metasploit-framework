# encoding: UTF-8

require 'spec_helper'

describe ArelHelpers::ArelTable do
  it "should add the [] function to the model and allow attribute access" do
    Post[:id].tap do |post_id|
      post_id.should be_a(Arel::Attribute)
      post_id.name.should == :id
      post_id.relation.name.should == "posts"
    end
  end

  it "should not interfere with associations" do
    post = Post.create(title: "I'm a little teapot")
    post.comments[0].should be_nil
  end

  it "should allow retrieving associated records" do
    post = Post.create(title: "I'm a little teapot")
    comment = post.comments.create
    post.reload.comments[0].id.should == comment.id
  end

  it "does not interfere with ActiveRecord::Relation objects" do
    Post.all[0].should be_nil
    p = Post.create(title: 'foo')
    Post.all[0].id.should == p.id
  end
end
