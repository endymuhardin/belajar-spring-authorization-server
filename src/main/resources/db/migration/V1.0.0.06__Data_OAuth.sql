insert into oauth2_registered_client (id, client_id, client_name,
      client_authentication_methods, client_secret, authorization_grant_types,
      redirect_uris, scopes, client_settings, token_settings)
values ('mobileapp', 'mobileapp', 'mobileapp',
        'basic,client_secret_basic', '$2a$10$sofxc4M7xltDyu4XynR7ouFDqGTr5BaTykK59wgsOopbMVjuBXQD6',
        'authorization_code,refresh_token', 'http://example.com,mobileapp:/authcode',
        'openid,message.read,message.write',
        '{"@class":"java.util.HashMap","setting.client.require-user-consent":true,"setting.client.require-proof-key":true}',
        '{"@class":"java.util.HashMap","setting.token.access-token-time-to-live":["java.time.Duration",300.000000000],"setting.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"setting.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"setting.token.reuse-refresh-tokens":true}')