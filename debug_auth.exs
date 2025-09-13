#!/usr/bin/env elixir

Mix.install([
  {:goth, "~> 1.4"},
  {:jason, "~> 1.4"},
  {:finch, "~> 0.16"}
])

defmodule DebugAuth do
  def run do
    IO.puts "=== Debugging AlloyDB IAM Authentication ==="
    
    # Start Goth with metadata service
    {:ok, _} = Goth.start_link(name: DebugGoth, source: {:metadata, []})
    {:ok, _} = Finch.start_link(name: DebugFinch)
    
    # Get token
    {:ok, token} = Goth.fetch(DebugGoth)
    IO.puts "1. Token retrieved: #{String.slice(token.token, 0, 40)}..."
    
    # Decode token to see the identity
    [_header, payload, _signature] = String.split(token.token, ".")
    {:ok, decoded} = payload |> Base.url_decode64(padding: false)
    claims = Jason.decode!(decoded)
    
    IO.puts "2. Token email: #{claims["email"]}"
    IO.puts "3. Token sub: #{claims["sub"]}"
    IO.puts "4. Token expires: #{claims["exp"]}"
    
    # Get service account from metadata
    url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
    request = Finch.build(:get, url, [{"Metadata-Flavor", "Google"}])
    {:ok, response} = Finch.request(request, DebugFinch)
    
    IO.puts "5. Metadata service account: #{response.body}"
    
    IO.puts "\n=== Required AlloyDB User ==="
    IO.puts "The AlloyDB IAM user should be created as: #{response.body}"
  end
end

DebugAuth.run()