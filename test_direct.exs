#!/usr/bin/env elixir

Mix.install([
  {:postgrex, "~> 0.17"},
  {:goth, "~> 1.4"},
  {:finch, "~> 0.16"}
])

defmodule TestDirect do
  def run do
    IO.puts "=== Testing Direct AlloyDB Connection ==="
    
    # Start services
    {:ok, _} = Goth.start_link(name: TestGoth, source: {:metadata, []})
    {:ok, _} = Finch.start_link(name: TestFinch)
    
    # Get token
    {:ok, %Goth.Token{token: token}} = Goth.fetch(TestGoth)
    IO.puts "1. Got OAuth token: #{String.slice(token, 0, 30)}..."
    
    # Get service account
    url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
    request = Finch.build(:get, url, [{"Metadata-Flavor", "Google"}])
    {:ok, response} = Finch.request(request, TestFinch)
    sa_email = String.trim(response.body)
    IO.puts "2. Service account: #{sa_email}"
    
    # Test connection WITHOUT SSL (just password auth)
    IO.puts "\n3. Testing connection WITHOUT SSL certificates..."
    opts = [
      hostname: "10.109.0.14",
      port: 5432,
      username: sa_email,
      password: token,
      database: "postgres",
      ssl: false,
      timeout: 10_000
    ]
    
    case Postgrex.start_link(opts) do
      {:ok, conn} ->
        IO.puts "   ✅ Connected successfully!"
        {:ok, result} = Postgrex.query(conn, "SELECT current_user", [])
        IO.puts "   Current user: #{inspect(result.rows)}"
      {:error, error} ->
        IO.puts "   ❌ Connection failed: #{inspect(error)}"
    end
    
    # Test with minimal SSL
    IO.puts "\n4. Testing connection WITH minimal SSL..."
    ssl_opts = [
      hostname: "10.109.0.14",
      port: 5432,
      username: sa_email,
      password: token,
      database: "postgres",
      ssl: true,
      timeout: 10_000
    ]
    
    case Postgrex.start_link(ssl_opts) do
      {:ok, conn} ->
        IO.puts "   ✅ Connected with SSL!"
        {:ok, result} = Postgrex.query(conn, "SELECT current_user", [])
        IO.puts "   Current user: #{inspect(result.rows)}"
      {:error, error} ->
        IO.puts "   ❌ SSL connection failed: #{inspect(error)}"
    end
  end
end

TestDirect.run()