defmodule FlexAuth.Plug.StoredSessionPlug do
  defmacro __using__(opts) do
    quote do
      import Plug.Conn

      defp get_resource(), do: unquote(Keyword.fetch!(opts, :get_resource))
      defp session_module(), do: unquote(Keyword.fetch!(opts, :session_module))
      defp endpoint_module(), do: unquote(Keyword.fetch!(opts, :endpoint_module))
      defp resource_name(), do: unquote(Keyword.fetch!(opts, :resource_name))
      defp token_timeout(), do: unquote(Keyword.get(opts, :token_timeout, 806_400))

      defp call_resource_function(mfa, conn, private_resource_id) when is_tuple(mfa) do
        apply(
          elem(mfa, 0),
          elem(mfa, 1),
          [conn, private_resource_id] ++ elem(mfa, 2)
        )
      end

      defp call_resource_function(function, conn, private_resource_id)
           when is_function(function) do
        apply(function, [private_resource_id])
      end

      defp fetch_auth_resource(conn) do
        private_resource_id = conn.private[:"auth_#{resource_name()}_id"]

        resource =
          private_resource_id &&
            call_resource_function(get_resource(), conn, private_resource_id)

        resource_id = if resource, do: resource.id, else: nil

        conn
        |> assign(:"current_#{resource_name()}", resource)
        |> put_session(:"current_#{resource_name()}_id", resource_id)
      end

      defp validate_session(conn) do
        case get_session(conn, :"session_#{resource_name()}_uuid") do
          nil ->
            conn
            |> put_session(:"session_#{resource_name()}_uuid", Ecto.UUID.generate())

          session_uuid ->
            conn
            |> validate_session_token(session_uuid)
        end
      end

      defp validate_session_token(conn, session_uuid) do
        case apply(session_module(), :get, [session_uuid]) do
          {:ok, token} ->
            case Phoenix.Token.verify(
                   endpoint_module(),
                   apply(session_module(), :signing_salt, []),
                   token,
                   max_age: token_timeout()
                 ) do
              {:ok, resource_id} ->
                put_private(conn, :"auth_#{resource_name()}_id", resource_id)

              _ ->
                conn
            end

          _ ->
            conn
        end
      end

      def init(opts), do: opts

      def call(conn, _opts) do
        conn
        |> validate_session()
        |> fetch_auth_resource()
      end
    end
  end
end
