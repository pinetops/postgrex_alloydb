# Start Finch for tests if not already started
unless Process.whereis(PostgrexAlloyDB.Finch) do
  {:ok, _} = Finch.start_link(name: PostgrexAlloyDB.Finch)
end

ExUnit.start(exclude: [:integration])
