defmodule FlexAuth.Session do
  @callback set(String.t(), String.t()) :: {:ok, term} | {:error, String.t()}
  @callback get(String.t()) :: {:ok, term} | {:error, String.t()}
  @callback signing_salt() :: String.t()
end
