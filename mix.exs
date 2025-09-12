defmodule PostgrexAlloydb.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/pinetops/postgrex_alloydb"

  def project do
    [
      app: :postgrex_alloydb,
      version: @version,
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      package: package(),
      description: "AlloyDB IAM authentication support for Postgrex",
      source_url: @source_url
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:goth, "~> 1.4"},
      {:postgrex, "~> 0.17 or ~> 0.18 or ~> 0.19", optional: true},
      {:jason, "~> 1.2"},
      {:finch, "~> 0.13"},
      {:ex_doc, "~> 0.30", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      main: "PostgrexAlloyDB",
      extras: ["README.md"],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp package do
    [
      maintainers: ["Tom Pinetops"],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url
      }
    ]
  end
end
