defmodule PostgrexAlloyDBTest do
  @moduledoc """
  Unit tests for PostgrexAlloyDB RSA keypair generation and validation.
  These tests don't require any external resources.
  """
  use ExUnit.Case

  alias PostgrexAlloyDB

  describe "RSA keypair generation" do
    test "generates and validates keypair" do
      {private_pem, public_pem} = PostgrexAlloyDB.generate_rsa_keypair()
      
      assert is_binary(private_pem)
      assert is_binary(public_pem)
      assert String.contains?(private_pem, "BEGIN RSA PRIVATE KEY")
      assert String.contains?(public_pem, "BEGIN RSA PUBLIC KEY")
      
      # Validate the keypair works
      assert PostgrexAlloyDB.validate_rsa_keypair(private_pem, public_pem) == true
    end

    test "generates different keypairs each time" do
      {private1, public1} = PostgrexAlloyDB.generate_rsa_keypair()
      {private2, public2} = PostgrexAlloyDB.generate_rsa_keypair()
      
      assert private1 != private2
      assert public1 != public2
    end

    test "works with different key sizes" do
      {private_2048, _public_2048} = PostgrexAlloyDB.generate_rsa_keypair(2048)
      {private_4096, _public_4096} = PostgrexAlloyDB.generate_rsa_keypair(4096)
      
      # 4096-bit key should be larger
      assert byte_size(private_4096) > byte_size(private_2048)
    end
  end

  describe "keypair validation" do
    test "validates matching keypairs" do
      {private, public} = PostgrexAlloyDB.generate_rsa_keypair()
      assert PostgrexAlloyDB.validate_rsa_keypair(private, public) == true
    end

    test "rejects mismatched keypairs" do
      {private1, _} = PostgrexAlloyDB.generate_rsa_keypair()
      {_, public2} = PostgrexAlloyDB.generate_rsa_keypair()
      
      assert PostgrexAlloyDB.validate_rsa_keypair(private1, public2) == false
    end

    test "handles invalid PEM gracefully" do
      {_, public} = PostgrexAlloyDB.generate_rsa_keypair()
      invalid_private = "invalid pem data"
      
      assert PostgrexAlloyDB.validate_rsa_keypair(invalid_private, public) == false
    end
  end

  describe "OTP 27 compatibility" do
    test "RSA record structure works correctly" do
      # This test verifies the fix for OTP 27 RSA record format
      {private_pem, public_pem} = PostgrexAlloyDB.generate_rsa_keypair()
      
      # Decode and verify the structure doesn't crash
      [private_entry] = :public_key.pem_decode(private_pem)
      private_key = :public_key.pem_entry_decode(private_entry)
      
      [public_entry] = :public_key.pem_decode(public_pem)
      public_key = :public_key.pem_entry_decode(public_entry)
      
      # Verify we can sign and verify (this would fail with incorrect record structure)
      test_data = "OTP 27 compatibility test"
      signature = :public_key.sign(test_data, :sha256, private_key)
      valid = :public_key.verify(test_data, :sha256, signature, public_key)
      
      assert valid == true
    end
  end
end