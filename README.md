# Keycloak Kubernetes Client Authenticator

The Keycloak Kubernetes Client Authenticator is
a [keycloak client authenticator](https://www.keycloak.org/docs/24.0.2/server_development/#_client_authentication). This
client authenticator that allows to use kubernetes service account token with specific audiences of `client_id` and
`client_secret` to get access token from keycloak.

## Configuring a client for use

1. Create a new client with your desired client id and set the description
   to `system:serviceaccount:<k8s-namespace>:<serviceAccountName>@<kubernetes-issuer-name>`: ![client description](doc/client-desc.png)
2. Select the `Kubernetes Service Account` Client Authenticator under `Credentials`
3. Import jwks

## How to get a token using the kubernetes service account token

To get an appropriate service account token mounted into your pod add the following volume specification:

```yaml
volumes:
  - name: keycloak-token
    projected:
      sources:
        - serviceAccountToken:
            path: keycloak-token
            audience: "<keycloak-issuer-url>"
            expirationSeconds: 7200
```

Then mount the volume `keycloak-token` on your desired place within your pod:

```yaml
volumeMounts:
  - mountPath: /var/tokens
    name: token
```

This request shows how to get a `client_credential`-token from keycloak:

```http request
POST https://<keycloak-base>/realms/<realm>/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type = client_credentials &
client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer &
client_assertion = <kubernetes-service-account-token from /var/tokens/keycloak-token>
```

## License

The Keycloak Kubernetes Client Authenticator is released under the Apache 2.0 license. See [LICENSE](LICENSE)
