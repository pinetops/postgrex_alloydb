#!/usr/bin/env elixir

Mix.install([
  {:postgrex, "~> 0.17"},
  {:jason, "~> 1.4"},
  {:finch, "~> 0.16"}
])

defmodule TestProxyConnection do
  def run do
    IO.puts "=== Testing AlloyDB Connection via Cloud Run Proxy ==="
    
    # The proxy endpoint
    proxy_host = "alloydb-proxy-882586158293.us-central1.run.app"
    
    IO.puts "1. Testing connection through proxy at: #{proxy_host}"
    
    # Try connecting through the proxy
    # The proxy handles the IAM authentication internally
    opts = [
      hostname: proxy_host,
      port: 5432,
      username: "postgres",  # Try default postgres user first
      password: "",  # Proxy handles auth
      database: "postgres",
      ssl: true,
      timeout: 10_000,
      connect_timeout: 10_000
    ]
    
    IO.puts "   Connecting to: #{opts[:hostname]}:#{opts[:port]}"
    IO.puts "   Username: #{opts[:username]}"
    
    case Postgrex.start_link(opts) do
      {:ok, conn} ->
        IO.puts "   ✅ Connected successfully through proxy!"
        
        # Run a simple query
        case Postgrex.query(conn, "SELECT current_user, version()", []) do
          {:ok, result} ->
            [[user, version]] = result.rows
            IO.puts "   Current user: #{user}"
            IO.puts "   Version: #{version}"
          {:error, error} ->
            IO.puts "   ❌ Query failed: #{inspect(error)}"
        end
        
      {:error, error} ->
        IO.puts "   ❌ Connection failed!"
        IO.puts "   Error: #{inspect(error)}"
        
        # Try with IAM user
        IO.puts "\n2. Trying with IAM service account user..."
        test_with_iam_user(proxy_host)
    end
  end
  
  defp test_with_iam_user(proxy_host) do
    username = "postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com"
    
    opts = [
      hostname: proxy_host,
      port: 5432,
      username: username,
      password: "",  # Proxy handles auth
      database: "postgres",
      ssl: true,
      timeout: 10_000,
      connect_timeout: 10_000
    ]
    
    IO.puts "   Username: #{username}"
    
    case Postgrex.start_link(opts) do
      {:ok, conn} ->
        IO.puts "   ✅ Connected with IAM user!"
        
        case Postgrex.query(conn, "SELECT current_user, version()", []) do
          {:ok, result} ->
            [[user, version]] = result.rows
            IO.puts "   Current user: #{user}"
            IO.puts "   Version: #{version}"
          {:error, error} ->
            IO.puts "   ❌ Query failed: #{inspect(error)}"
        end
        
      {:error, error} ->
        IO.puts "   ❌ Connection failed with IAM user!"
        IO.puts "   Error: #{inspect(error)}"
    end
  end
end

TestProxyConnection.run()