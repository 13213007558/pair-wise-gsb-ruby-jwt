# frozen_string_literal: true

module JWT
  module JWE
    # RSAES-OAEP using SHA-256 for both the OAEP hash and MGF1.
    module RsaOaep256
      HASH_LENGTH = 32
      module_function

      def encrypt(public_key, data)
        validate_rsa_key_for_encryption!(public_key, data)
        label_hash = OpenSSL::Digest::SHA256.digest('')
        encoded_message = encode_message(public_key.n.num_bytes, data, label_hash)
        raw_rsa_operation(public_key, encoded_message, :public_encrypt)
      end

      def decrypt(private_key, encrypted_data, expected_length:)
        validate_rsa_key_for_decryption!(private_key)
        raise JWT::VerificationError, 'JWE decryption failed' unless encrypted_data.bytesize == private_key.n.num_bytes

        modulus_length = private_key.n.num_bytes
        encoded_message = raw_rsa_operation(private_key, encrypted_data, :private_decrypt)
        encoded_message = left_pad(encoded_message, modulus_length)
        label_hash = OpenSSL::Digest::SHA256.digest('')
        data = decode_message(encoded_message, modulus_length, label_hash)
        raise JWT::VerificationError, 'JWE decryption failed' unless data.bytesize == expected_length

        data
      end

      def validate_rsa_key_for_encryption!(key, data)
        raise JWT::EncodeError, 'Invalid RSA-OAEP-256 key or data' unless valid_encryption_key?(key, data)
      end

      def validate_rsa_key_for_decryption!(key)
        unless key.is_a?(OpenSSL::PKey::RSA) && key.private? && key.n.num_bits >= 2048
          raise JWT::DecodeError, 'An RSA private key is required for decryption'
        end
      end

      def valid_encryption_key?(key, data)
        key.is_a?(OpenSSL::PKey::RSA) &&
          key.n.num_bits >= 2048 &&
          data.bytesize <= key.n.num_bytes - (2 * HASH_LENGTH) - 2
      end

      def raw_rsa_operation(key, data, method)
        key.public_send(method, data, OpenSSL::PKey::RSA::NO_PADDING)
      rescue OpenSSL::PKey::PKeyError, ArgumentError, OpenSSL::Cipher::CipherError
        raise JWT::VerificationError, 'JWE decryption failed'
      end

      def encode_message(modulus_length, data, label_hash)
        seed = SecureRandom.random_bytes(HASH_LENGTH)
        padding_length = modulus_length - (2 * HASH_LENGTH) - 2 - data.bytesize
        raise JWT::EncodeError, 'Invalid RSA-OAEP-256 key or data' if padding_length.negative?

        data_block = (label_hash + ("\x00" * padding_length) + [1].pack('C') + data).b
        masked_data_block = xor(data_block, mgf1(seed, modulus_length - HASH_LENGTH - 1))
        masked_seed = xor(seed, mgf1(masked_data_block, HASH_LENGTH))
        "\x00" + masked_seed + masked_data_block
      end

      def decode_message(encoded_message, modulus_length, label_hash)
        if encoded_message.bytesize != modulus_length || encoded_message.getbyte(0) != 0
          raise JWT::VerificationError, 'JWE decryption failed'
        end

        masked_seed = encoded_message.byteslice(1, HASH_LENGTH)
        masked_data_block = encoded_message.byteslice(1 + HASH_LENGTH, modulus_length - HASH_LENGTH - 1)
        seed = xor(masked_seed, mgf1(masked_data_block, HASH_LENGTH))
        data_block = xor(masked_data_block, mgf1(seed, masked_data_block.bytesize))

        validate_data_block!(data_block, label_hash)
        separator = data_block.index("\x01", 2 * HASH_LENGTH)
        data_block.byteslice(separator + 1, data_block.bytesize - separator - 1)
      end

      def validate_data_block!(data_block, label_hash)
        separator = data_block.index("\x01", 2 * HASH_LENGTH)

        unless data_block.bytesize > 2 * HASH_LENGTH &&
               data_block.byteslice(0, HASH_LENGTH) == label_hash &&
               separator &&
               data_block.byteslice(HASH_LENGTH, separator - HASH_LENGTH).each_byte.all?(&:zero?)
          raise JWT::VerificationError, 'JWE decryption failed'
        end
      end

      def mgf1(seed, length)
        raise JWT::VerificationError, 'JWE decryption failed' if length.negative? || length > (2**32) * HASH_LENGTH

        counter = 0
        result = String.new(encoding: Encoding::BINARY)
        while result.bytesize < length
          result << OpenSSL::Digest::SHA256.digest(seed + [counter].pack('N'))
          counter += 1
        end
        result.byteslice(0, length)
      end

      def xor(left, right)
        raise JWT::VerificationError, 'JWE decryption failed' unless left.bytesize == right.bytesize

        left.bytes.each_with_index.each_with_object(String.new(encoding: Encoding::BINARY)) do |(byte, index), result|
          result << (byte ^ right.getbyte(index))
        end.force_encoding(Encoding::BINARY)
      end

      def left_pad(data, length)
        return data if data.bytesize >= length

        ("\x00" * (length - data.bytesize)) + data
      end
    end
  end
end
