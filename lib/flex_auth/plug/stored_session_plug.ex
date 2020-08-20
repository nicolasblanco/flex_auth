defmodule FlexAuth.Plug.StoredSessionPlug do
  defmacro __using__(opts) do
    quote do
      import Plug.Conn

      def get_resource_function(), do: unquote(Keyword.fetch!(opts, :get_resource_function))
      def session_module(), do: unquote(Keyword.fetch!(opts, :session_module))
      def endpoint(), do: unquote(Keyword.fetch!(opts, :endpoint))
      def resource_name(), do: unquote(Keyword.fetch!(opts, :resource_name))

      defp fetch_auth_resource(conn) do
        resource =
          conn.private[:"auth_#{resource_name()}_id"] &&
            apply(get_resource_function(), [conn.private[:"auth_#{resource_name()}_id"]])

        resource_id = if resource, do: resource.id, else: nil

        conn
        |> assign(:"current_#{resource_name()}", resource)
        |> put_session(:"current_#{resource_name()}_id", resource_id)
      end

      defp validate_session(conn) do
        case get_session(conn, :"session_uuid_#{resource_name()}") do
          nil ->
            conn
            |> put_session(:"session_uuid_#{resource_name()}", Ecto.UUID.generate())

          session_uuid ->
            conn
            |> validate_session_token(session_uuid)
        end
      end

      defp validate_session_token(conn, session_uuid) do
        case apply(session_module(), :get, [session_uuid]) do
          {:ok, token} ->
            case Phoenix.Token.verify(
                   endpoint(),
                   apply(session_module(), :signing_salt, []),
                   token,
                   max_age: 806_400
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
