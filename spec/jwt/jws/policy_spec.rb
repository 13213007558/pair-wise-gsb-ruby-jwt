# frozen_string_literal: true

RSpec.describe JWT::JWS::Policy do
  def result(signature: nil, error: nil, key: nil)
    signature ||= Object.new
    JWT::JWS::SignatureResult.new(signature: signature, error: error, key: key)
  end

  describe '.build' do
    it 'builds the all signatures policy by default' do
      expect(described_class.build(nil)).to be_a(JWT::JWS::Policy::AllSignatures)
      expect(described_class.build(:all)).to be_a(JWT::JWS::Policy::AllSignatures)
    end

    it 'builds a threshold from an integer' do
      expect(described_class.build(2)).to be_a(JWT::JWS::Policy::Threshold)
    end

    it 'builds a threshold from a hash' do
      expect(described_class.build(minimum: 2)).to be_a(JWT::JWS::Policy::Threshold)
      expect(described_class.build(threshold: 3).minimum).to eq(3)
    end

    it 'rejects thresholds without a minimum' do
      expect { described_class.build({}) }.to raise_error(ArgumentError, /:minimum/)
    end

    it 'rejects non positive thresholds' do
      expect { described_class.build(0) }.to raise_error(ArgumentError, /positive integer/)
    end

    it 'rejects unknown policies' do
      expect { described_class.build(:bogus) }.to raise_error(ArgumentError, /Unknown JWS verification policy/)
    end
  end

  describe JWT::JWS::Policy::AllSignatures do
    subject(:policy) { described_class.new }

    let(:key_a) { 'a' * 32 }
    let(:key_b) { 'b' * 32 }

    it 'is satisfied when all signatures come from distinct keys' do
      results = [result(key: key_a), result(key: key_b)]

      expect(policy.satisfied?(results)).to be(true)
    end

    it 'is not satisfied when one signature is invalid' do
      results = [result(key: key_a), result(error: JWT::VerificationError.new('bad'))]

      expect(policy.satisfied?(results)).to be(false)
    end

    it 'is not satisfied when the same key signed twice' do
      results = [result(key: key_a), result(key: key_a)]

      expect(policy.satisfied?(results)).to be(false)
    end

    it 'is not satisfied without signatures' do
      expect(policy.satisfied?([])).to be(false)
    end
  end

  describe JWT::JWS::Policy::Threshold do
    subject(:policy) { described_class.new(2) }

    let(:key_a) { 'a' * 32 }
    let(:key_b) { 'b' * 32 }
    let(:key_c) { 'c' * 32 }

    it 'is satisfied when enough distinct keys verified' do
      results = [result(key: key_a), result(key: key_b), result(error: JWT::VerificationError.new('bad'))]

      expect(policy.satisfied?(results)).to be(true)
    end

    it 'is not satisfied when duplicate signatures from one key stay below the threshold' do
      results = [result(key: key_a), result(key: key_a), result(error: JWT::VerificationError.new('bad'))]

      expect(policy.satisfied?(results)).to be(false)
    end

    it 'ignores invalid siblings once enough distinct keys verified' do
      results = [result(key: key_a), result(key: key_b), result(key: key_b), result(error: JWT::VerificationError.new('bad'))]

      expect(policy.satisfied?(results)).to be(true)
    end
  end
end
