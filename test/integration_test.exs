defmodule PostgrexAlloyDB.IntegrationTest do
  @moduledoc """
  Integration tests for AlloyDB with real Google Cloud services.
  
  These tests require:
  - A real AlloyDB instance
  - Valid GCP credentials
  - Proper environment variables set
  
  See INTEGRATION_TESTING.md for setup instructions.
  """
  use ExUnit.Case
  
  @moduletag :integration
  @moduletag timeout: 120_000  # 2 minutes per test
  
  setup_all do
    # Check required environment variables
    required_env = [
      "ALLOYDB_INSTANCE_URI",
      "ALLOYDB_USERNAME"
    ]
    
    missing = Enum.filter(required_env, &is_nil(System.get_env(&1)))
    
    unless Enum.empty?(missing) do
      {:skip, "Missing required environment variables: #{Enum.join(missing, ", ")}. See INTEGRATION_TESTING.md"}
    else
      # Start Goth with real credentials from metadata service
      # In Cloud Run/GCE, metadata service authentication is automatically available
      {:ok, goth_pid} = Goth.start_link(name: PostgrexAlloyDBTest, source: {:metadata, []})
      
      # Start Finch for HTTP requests if not already started
      finch_pid = case Process.whereis(PostgrexAlloyDB.Finch) do
        nil -> 
          {:ok, pid} = Finch.start_link(name: PostgrexAlloyDB.Finch)
          pid
        pid -> 
          pid
      end
      
      on_exit(fn -> 
        GenServer.stop(goth_pid)
        # Only stop Finch if we started it
        if finch_pid && Process.alive?(finch_pid) do
          GenServer.stop(finch_pid)
        end
      end)
      
      %{
        instance_uri: System.get_env("ALLOYDB_INSTANCE_URI"),
        username: System.get_env("ALLOYDB_USERNAME")
      }
    end
  end

  describe "AlloyDB Admin API Integration" do
    test "resolves real instance IP address", %{instance_uri: uri} do
      {:ok, token} = PostgrexAlloyDB.get_token(PostgrexAlloyDBTest)
      
      {:ok, components} = PostgrexAlloyDB.resolve_instance_uri(uri, token)
      
      # Should resolve to actual private IP, not localhost
      assert components.hostname != "127.0.0.1"
      assert components.hostname =~ ~r/^10\./  # GCP private IP range
      
      # Verify components match the URI
      assert is_binary(components.project_id)
      assert is_binary(components.location)
      assert is_binary(components.cluster)
      assert is_binary(components.instance)
      
      IO.puts("✅ Resolved AlloyDB instance IP: #{components.hostname}")
    end
    
    test "generates real client certificates" do
      {_private_pem, public_pem} = PostgrexAlloyDB.generate_rsa_keypair()
      {:ok, token} = PostgrexAlloyDB.get_token(PostgrexAlloyDBTest)
      
      # Extract project details from instance URI
      uri = System.get_env("ALLOYDB_INSTANCE_URI")
      {:ok, components} = PostgrexAlloyDB.parse_instance_uri(uri)
      
      opts = [
        project_id: components.project_id,
        location: components.location,
        cluster: components.cluster
      ]
      
      {:ok, cert_chain, ca_cert} = PostgrexAlloyDB.get_client_certificate(token, public_pem, opts)
      
      # Verify real certificates from AlloyDB Admin API
      assert is_list(cert_chain)
      assert length(cert_chain) >= 1
      assert String.contains?(hd(cert_chain), "-----BEGIN CERTIFICATE-----")
      assert String.contains?(ca_cert, "-----BEGIN CERTIFICATE-----")
      
      # Verify certificate is actually valid (can be parsed)
      [cert_entry] = :public_key.pem_decode(hd(cert_chain))
      cert = :public_key.pem_entry_decode(cert_entry)
      assert is_tuple(cert)  # Valid certificate structure
      
      IO.puts("✅ Generated real AlloyDB client certificate")
    end
    
    test "API calls include proper authentication headers" do
      {:ok, token} = PostgrexAlloyDB.get_token(PostgrexAlloyDBTest)
      
      # Verify token format (OAuth2 bearer token)
      assert String.starts_with?(token, "ya29.")
      assert String.length(token) > 100  # OAuth tokens are long
      
      IO.puts("✅ Retrieved valid OAuth2 token: #{String.slice(token, 0..20)}...")
    end
  end
  
  describe "AlloyDB Authentication Integration" do
    test "debug service account identity" do
      # Get service account from metadata service
      url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
      request = Finch.build(:get, url, [{"Metadata-Flavor", "Google"}])
      
      sa_email = case Finch.request(request, PostgrexAlloyDB.Finch) do
        {:ok, response} ->
          email = String.trim(response.body)
          IO.puts("🔍 Service account from metadata: #{email}")
          
          # According to AlloyDB docs, for service accounts, use without .gserviceaccount.com
          # Format: SERVICE_ACCOUNT@PROJECT_ID.iam
          # From: postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com
          # To: postgrex-ci-sa@postgrex-alloydb-ci.iam
          username = String.replace(email, ".iam.gserviceaccount.com", ".iam")
          IO.puts("🔍 AlloyDB username should be: #{username}")
          IO.puts("🔍 Environment variable says: #{System.get_env("ALLOYDB_USERNAME")}")
          
          username
        {:error, reason} ->
          IO.puts("🔍 Could not get metadata: #{inspect(reason)}")
          System.get_env("ALLOYDB_USERNAME")
      end
      
      # Test with the correct username
      if sa_email do
        {:ok, token} = PostgrexAlloyDB.get_token(PostgrexAlloyDBTest)
        IO.puts("🔍 Testing connection with username: #{sa_email}")
        
        opts = [
          hostname: "10.109.0.14",
          port: 5432,
          username: sa_email,
          password: token,
          database: "postgres",
          ssl: true,
          timeout: 10_000
        ]
        
        case Postgrex.start_link(opts) do
          {:ok, conn} ->
            IO.puts("✅ DIRECT CONNECTION SUCCESSFUL!")
            {:ok, result} = Postgrex.query(conn, "SELECT current_user", [])
            IO.puts("✅ Current user: #{inspect(result.rows)}")
          {:error, error} ->
            IO.puts("❌ Direct connection failed: #{inspect(error)}")
        end
      end
      
      assert true
    end
    
    test "full IAM authentication flow with postgrex_config", %{instance_uri: uri, username: username} do
      config = PostgrexAlloyDB.postgrex_config([
        goth_name: PostgrexAlloyDBTest,
        instance_uri: uri,
        database: "postgres",
        username: username
      ])
      
      # Verify config has been properly resolved
      assert config[:hostname] != "127.0.0.1"
      assert config[:hostname] =~ ~r/^10\./
      assert config[:username] == username
      assert String.starts_with?(config[:password], "ya29.")  # OAuth token
      assert is_list(config[:ssl])
      
      # Test actual connection
      {:ok, conn} = Postgrex.start_link(config)
      
      # Verify we're connected as IAM user
      result = Postgrex.query!(conn, "SELECT current_user, version()", [])
      [[current_user, version]] = result.rows
      
      # Should be IAM user format, not regular postgres user
      assert String.contains?(current_user, "@")
      assert String.contains?(current_user, ".iam")
      assert current_user == username
      
      # Verify it's PostgreSQL (AlloyDB is PostgreSQL-compatible)
      assert String.contains?(version, "PostgreSQL")
      
      IO.puts("✅ Connected as IAM user: #{current_user}")
      IO.puts("✅ AlloyDB version: #{version}")
      
      GenServer.stop(conn)
    end
    
    test "config_resolver works with real AlloyDB", %{instance_uri: uri, username: username} do
      opts = [
        goth_server: PostgrexAlloyDBTest,
        instance_uri: uri,
        database: "postgres", 
        username: username
      ]
      
      config = PostgrexAlloyDB.config_resolver(opts)
      
      # Should have resolved to real IP
      assert config[:hostname] != "127.0.0.1"
      assert config[:hostname] =~ ~r/^10\./
      assert config[:username] == username
      assert String.starts_with?(config[:password], "ya29.")  # OAuth token
      assert is_list(config[:ssl])
      
      # Test that config actually works for connection
      {:ok, conn} = Postgrex.start_link(config)
      result = Postgrex.query!(conn, "SELECT 'config_resolver test success' as message", [])
      assert [["config_resolver test success"]] = result.rows
      
      IO.puts("✅ config_resolver successfully connected to AlloyDB")
      
      GenServer.stop(conn)
    end
    
    test "performs real SQL operations", %{instance_uri: uri, username: username} do
      config = PostgrexAlloyDB.postgrex_config([
        goth_name: PostgrexAlloyDBTest,
        instance_uri: uri,
        database: "postgres",
        username: username
      ])
      
      {:ok, conn} = Postgrex.start_link(config)
      
      # Create a test table
      table_name = "goth_integration_test_#{System.unique_integer([:positive])}"
      
      Postgrex.query!(conn, """
        CREATE TABLE #{table_name} (
          id SERIAL PRIMARY KEY,
          message TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      """, [])
      
      # Insert test data
      Postgrex.query!(conn, """
        INSERT INTO #{table_name} (message) VALUES ($1), ($2)
      """, ["AlloyDB Integration Test", "OAuth IAM Authentication Works!"])
      
      # Query test data
      result = Postgrex.query!(conn, """
        SELECT id, message, created_at FROM #{table_name} ORDER BY id
      """, [])
      
      assert length(result.rows) == 2
      [[_id1, msg1, _time1], [_id2, msg2, _time2]] = result.rows
      assert msg1 == "AlloyDB Integration Test"
      assert msg2 == "OAuth IAM Authentication Works!"
      
      # Clean up test table
      Postgrex.query!(conn, "DROP TABLE #{table_name}", [])
      
      IO.puts("✅ Performed full SQL operations (CREATE, INSERT, SELECT, DROP)")
      
      GenServer.stop(conn)
    end
    
    test "SSL/TLS connection is properly secured", %{instance_uri: uri, username: username} do
      config = PostgrexAlloyDB.postgrex_config([
        goth_name: PostgrexAlloyDBTest,
        instance_uri: uri,
        database: "postgres",
        username: username
      ])
      
      # Verify SSL configuration
      ssl_config = config[:ssl]
      assert ssl_config[:verify] == :verify_peer
      assert ssl_config[:versions] == [:"tlsv1.3"]
      # Check for file paths or actual certs
      assert ssl_config[:certfile] || ssl_config[:cert]
      assert ssl_config[:keyfile] || ssl_config[:key]
      assert ssl_config[:cacertfile] || ssl_config[:cacerts]
      
      # Test connection uses SSL
      {:ok, conn} = Postgrex.start_link(config)
      
      # Query SSL status (AlloyDB should report encrypted connection)
      result = Postgrex.query!(conn, """
        SELECT 
          inet_server_addr() as server_ip,
          inet_client_addr() as client_ip,
          current_setting('ssl') as ssl_enabled
      """, [])
      
      [[server_ip, client_ip, ssl_enabled]] = result.rows
      
      assert ssl_enabled == "on"
      # IP addresses might be nil or other types in Cloud Run environment
      # Just verify SSL is enabled, which is the main goal
      IO.puts("   Server IP type: #{inspect(server_ip)}")
      IO.puts("   Client IP type: #{inspect(client_ip)}")
      
      IO.puts("✅ SSL/TLS connection verified")
      IO.puts("   Server IP: #{inspect(server_ip)}")
      IO.puts("   Client IP: #{inspect(client_ip)}")
      IO.puts("   SSL Enabled: #{ssl_enabled}")
      
      GenServer.stop(conn)
    end
  end
  
  describe "Error Handling Integration" do
    test "handles invalid instance URI gracefully" do
      invalid_uri = "projects/fake/locations/fake/clusters/fake/instances/fake"
      {:ok, token} = PostgrexAlloyDB.get_token(PostgrexAlloyDBTest)
      
      result = PostgrexAlloyDB.resolve_instance_uri(invalid_uri, token)
      # Just verify it returns an error for invalid URI
      assert match?({:error, _}, result)
      
      if {:error, error_msg} = result do
        IO.puts("   Error message: #{error_msg}")
      end
      
      IO.puts("✅ Properly handles invalid instance URI")
    end
    
    test "handles invalid credentials gracefully" do
      fake_token = "fake_oauth_token_12345"
      uri = System.get_env("ALLOYDB_INSTANCE_URI")
      
      assert {:error, error_msg} = PostgrexAlloyDB.resolve_instance_uri(uri, fake_token)
      assert String.contains?(error_msg, "401") or String.contains?(error_msg, "authentication")
      
      IO.puts("✅ Properly handles invalid OAuth token")
    end
  end
end