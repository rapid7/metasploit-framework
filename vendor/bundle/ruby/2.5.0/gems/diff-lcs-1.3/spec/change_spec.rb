# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe Diff::LCS::Change do
  describe "an add" do
    subject { described_class.new('+', 0, 'element') }
    it { should_not be_deleting   }
    it { should     be_adding     }
    it { should_not be_unchanged  }
    it { should_not be_changed    }
    it { should_not be_finished_a }
    it { should_not be_finished_b }
  end

  describe "a delete" do
    subject { described_class.new('-', 0, 'element') }
    it { should     be_deleting   }
    it { should_not be_adding     }
    it { should_not be_unchanged  }
    it { should_not be_changed    }
    it { should_not be_finished_a }
    it { should_not be_finished_b }
  end

  describe "an unchanged" do
    subject { described_class.new('=', 0, 'element') }
    it { should_not be_deleting   }
    it { should_not be_adding     }
    it { should     be_unchanged  }
    it { should_not be_changed    }
    it { should_not be_finished_a }
    it { should_not be_finished_b }
  end

  describe "a changed" do
    subject { described_class.new('!', 0, 'element') }
    it { should_not be_deleting   }
    it { should_not be_adding     }
    it { should_not be_unchanged  }
    it { should     be_changed    }
    it { should_not be_finished_a }
    it { should_not be_finished_b }
  end

  describe "a finished_a" do
    subject { described_class.new('>', 0, 'element') }
    it { should_not be_deleting   }
    it { should_not be_adding     }
    it { should_not be_unchanged  }
    it { should_not be_changed    }
    it { should     be_finished_a }
    it { should_not be_finished_b }
  end

  describe "a finished_b" do
    subject { described_class.new('<', 0, 'element') }
    it { should_not be_deleting   }
    it { should_not be_adding     }
    it { should_not be_unchanged  }
    it { should_not be_changed    }
    it { should_not be_finished_a }
    it { should     be_finished_b }
  end
end
