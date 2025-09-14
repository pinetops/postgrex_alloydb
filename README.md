# PostgrexAlloyDB

AlloyDB IAM authentication support for Postgrex connections.

## Features

- OAuth2 token authentication via [Goth](https://hex.pm/packages/goth)
- Native Elixir RSA keypair generation (no OpenSSL dependency)
- Automatic client certificate generation via AlloyDB Admin API
- TLS 1.3 mutual authentication
- Support for both IAM and native database authentication
- Dynamic credential refresh with Postgrex config_resolver
- Automatic IP resolution for AlloyDB instances

## Installation

Add `postgrex_alloydb` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:postgrex_alloydb, "~> 0.1.0"},
    {:goth, "~> 1.4"},
    {:postgrex, "~> 0.17"}
  ]
end
```

## Usage

### Basic Connection

```elixir
# Start Goth for authentication
{:ok, _} = Goth.start_link(name: MyApp.Goth, source: {:metadata, []})

# Connect to AlloyDB with IAM authentication
config = PostgrexAlloyDB.postgrex_config(
  goth_name: MyApp.Goth,
  instance_uri: "projects/my-project/locations/us-central1/clusters/prod/instances/primary",
  database: "postgres",
  username: "myapp@myproject.iam"
)

{:ok, conn} = Postgrex.start_link(config)
```

### Ecto Integration

Configure your repo to use the AlloyDB config resolver:

```elixir
# config/runtime.exs
config :my_app, MyApp.Repo,
  instance_uri: System.get_env("ALLOYDB_INSTANCE_URI"),
  database: "postgres",
  username: System.get_env("ALLOYDB_USERNAME"),
  goth_server: MyApp.Goth,
  config_resolver: &PostgrexAlloyDB.config_resolver/1

# lib/my_app/application.ex
def start(_type, _args) do
  children = [
    {Goth, name: MyApp.Goth, source: {:metadata, []}},
    MyApp.Repo
  ]
  
  Supervisor.start_link(children, strategy: :one_for_one)
end
```

## CI Status

CI/CD pipeline configured with Google Cloud Build for automated testing on every push and PR.

## License

Apache License 2.0

