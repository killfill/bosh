require 'spec_helper'

describe 'Dummy Stemcell' do
  context 'installed by system_parameters' do
    describe file('/var/vcap/bosh/etc/infrastructure') do
      it { should contain('dummy') }
    end
  end
end
