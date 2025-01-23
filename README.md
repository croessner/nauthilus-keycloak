# Nauthilus authenticator for keycloak

This is a demo authenticator that replaces the default "username and password form" authenticator. It redirects
authentication attempts to Nauthilus. Upon a successful respone, an account name is returned to Keycloak, which must match an already known user on the system.

## Build

```shell
mvn clean package
```

## Install

Copy the jar file into your keycloak environment and restart the service.

You must set at least one environment variable named NAUTHILUS_LOGIN_URL, which should look similar to this string:

```
NAUTHILUS_LOGIN_URL=https://login.example.com/api/v1/auth/json
```

If your Nauthilus-server requires HTTP Basic authorization, please also add these variables:

```
NAUTHILUS_USERNAME
NAUTHILUS_PASSWORD
```

## Configure

You can find the "Nauthilus authenticator" in your flows. It replaces the default
"Username and password form" execution step.

For example copy the browser flow and replace the authenticator with the Nauthilus version.

Nauthilus returns an account name. Keycloak must know about this user. Else the authentication step will fail.

Here is a simple yaml-blob for nauthilus.yml in a LDAP section:

```yml
ldap:

  config:
    lookup_pool_size: 8
    lookup_idle_pool_size: 4

    auth_pool_size: 16
    auth_idle_pool_size: 5

    server_uri: ldap://ldap.example.com:389/
    starttls: true
    tls_skip_verify: true
    tls_ca_cert: /etc/nauthilus/ssl/certs/yourcacert.crt

  search:

    - protocol: keycloak
    cache_name: keycloak
    base_dn: ou=people,dc=example,dc=com
    filter:
      user: |
        (&
          (objectClass=inetOrgPerson)
          (uniqueIdentifier=%L{user})
        )
    mapping:
      account_field: uniqueIdentifier
    attribute:
      - uniqueIdentifier
```

The configuration must match your settings in keycloak. I have configured a user federation with LDAP, where the settings match with the Nauthilus settings.

