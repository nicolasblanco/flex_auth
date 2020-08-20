defmodule FlexAuth.SessionHelper do
  defmacro __using__(opts) do
    quote do
      import Plug.Conn, only: [put_session: 3, get_session: 2]

      defp session_module(), do: unquote(Keyword.fetch!(opts, :session_module))
      defp endpoint_module(), do: unquote(Keyword.fetch!(opts, :endpoint_module))
      defp resource_name(), do: unquote(Keyword.fetch!(opts, :resource_name))

      def sign_out(conn) do
        conn
        |> put_session(:"session_#{resource_name()}_uuid", nil)
        |> put_session(:"current_#{resource_name()}_id", nil)
      end

      def sign_in(conn, resource) do
        resource_id = Map.fetch!(resource, :id)

        {:ok, _} =
          conn
          |> get_session_uuid()
          |> perform_sign_in(resource_id)

        conn
      end

      def get_session_uuid(conn) do
        get_session(conn, :"session_#{resource_name()}_uuid") ||
          raise "missing conn key session_#{resource_name()}_uuid, is the plug fetching this resource previously called?"
      end

      def perform_sign_in(key, resource_id) do
        salt = apply(session_module(), :signing_salt, [])
        token = Phoenix.Token.sign(endpoint_module(), salt, resource_id)

        apply(session_module(), :set, [key, token])
      end
    end
  end
end
