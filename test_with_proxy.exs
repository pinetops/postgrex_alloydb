#!/usr/bin/env elixir

Mix.install([
  {:postgrex, "~> 0.17"}
])

defmodule TestWithProxy do
  def run do
    IO.puts "=== Testing AlloyDB Connection via Auth Proxy ==="
    
    # When using the proxy, we don't need OAuth tokens
    # The proxy handles IAM authentication
    
    opts = [
      hostname: "127.0.0.1",  # Proxy runs locally
      port: 5432,
      username: "postgres",   # Use default postgres user
      password: "",           # No password needed with proxy
      database: "postgres",
      ssl: false,             # Proxy handles SSL to AlloyDB
      timeout: 10_000
    ]
    
    IO.puts "Connecting through AlloyDB Auth Proxy at localhost:5432..."
    
    case Postgrex.start_link(opts) do
      {:ok, conn} ->
        IO.puts "✅ Connected successfully through proxy!"
        
        {:ok, result} = Postgrex.query(conn, "SELECT current_user, version()", [])
        [[user, version]] = result.rows
        IO.puts "Current user: #{user}"
        IO.puts "Database version: #{version}"
        
        # Test a simple query
        {:ok, result} = Postgrex.query(conn, "SELECT 'Proxy connection works!' as message", [])
        [[message]] = result.rows
        IO.puts "Message: #{message}"
        
      {:error, error} ->
        IO.puts "❌ Connection failed: #{inspect(error)}"
        System.halt(1)
    end
  end
end

TestWithProxy.run()