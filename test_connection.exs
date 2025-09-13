#!/usr/bin/env elixir

Mix.install([
  {:postgrex, "~> 0.17"},
  {:jason, "~> 1.4"},
  {:finch, "~> 0.16"}
])

defmodule TestConnection do
  def run do
    IO.puts "=== Testing AlloyDB Connection ==="
    
    # Get OAuth token from metadata service
    IO.puts "1. Getting OAuth token..."
    token = get_oauth_token()
    IO.puts "   Token: #{String.slice(token, 0, 20)}..."
    
    # Test direct connection
    IO.puts "\n2. Testing direct connection to AlloyDB..."
    
    username = System.get_env("ALLOYDB_USERNAME") || "postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com"
    
    opts = [
      hostname: "10.109.0.14",
      port: 5432,
      username: username,
      password: token,
      database: "postgres",
      ssl: true,
      timeout: 10_000,
      connect_timeout: 10_000
    ]
    
    IO.puts "   Host: #{opts[:hostname]}"
    IO.puts "   User: #{username}"
    
    case Postgrex.start_link(opts) do
      {:ok, conn} ->
        IO.puts "   ✅ Connected successfully!"
        
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
    end
  end
  
  defp get_oauth_token do
    url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    headers = [{"Metadata-Flavor", "Google"}]
    
    {:ok, _} = Finch.start_link(name: MyFinch)
    
    request = Finch.build(:get, url, headers)
    
    case Finch.request(request, MyFinch) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        %{"access_token" => token} = Jason.decode!(body)
        token
      {:error, reason} ->
        IO.puts "Failed to get token: #{inspect(reason)}"
        ""
    end
  end
end

TestConnection.run()