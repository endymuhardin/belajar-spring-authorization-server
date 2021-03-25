# Belajar Spring Authorization Server #

Contoh kode program [Spring Authorization Server yang baru](https://spring.io/blog/2020/11/10/spring-authorization-server-0-0-3-available-now).

Cara menjalankan aplikasi

```
mvn clean spring-boot:run
```

## Mendapatkan Access Token dengan Grant Type Authorization Code ##

1. Cari tahu dulu URL yang digunakan untuk prosedur OAuth 2.0

    ```
    curl http://localhost:9000/.well-known/openid-configuration
    ```
   
    Hasilnya seperti ini

    ```json
    {
        "issuer": "http://127.0.0.1:9000",
        "authorization_endpoint": "http://127.0.0.1:9000/oauth2/authorize",
        "token_endpoint": "http://127.0.0.1:9000/oauth2/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "jwks_uri": "http://127.0.0.1:9000/oauth2/jwks",
        "response_types_supported": [
          "code"
        ],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token"
        ],
        "subject_types_supported": [
          "public"
        ],
        "id_token_signing_alg_values_supported": [
          "RS256"
        ],
        "scopes_supported": [
          "openid"
        ]
    }
    ```

2. Akses `authorization_endpoint` di [http://127.0.0.1:9000/oauth2/authorize?client_id=belajar&redirect_uri=http://example.com&response_type=code](http://127.0.0.1:9000/oauth2/authorize). 
   
    [![Halaman login](./img/login.png)](./img/login.png)

    Login dengan username `user001` dan password `teststaff`

3. Approve consent page

    [![Consent Page](./img/consent-page.png)](./img/consent-page.png)

3. Dapatkan `authorization_code` setelah berhasil login, misalnya `4KVvk3r1UNqAMJdr8lzBDdaO8HammyuBhm4E5C-YIz01J4cxaFY7xmAYlmWepflvpL6VNES4_yyUFcTmE2dHJGrtWVDnGmHhKzvz7GwyAoo7ZsLVcW9LWf-72COIJSxv`

    [![Redirect Page](./img/authcode.png)](./img/authcode.png)

4. Tukarkan `authorization_code` menjadi `access_token`

    ```
    curl --location --request POST 'http://127.0.0.1:9000/oauth2/token' \
      --header 'Authorization: Basic YmVsYWphcjpiZWxhamFyMTIz' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --header 'Cookie: JSESSIONID=EE4C292A9FC39CABC9313DB6542C3A1C' \
      --data-urlencode 'code=4KVvk3r1UNqAMJdr8lzBDdaO8HammyuBhm4E5C-YIz01J4cxaFY7xmAYlmWepflvpL6VNES4_yyUFcTmE2dHJGrtWVDnGmHhKzvz7GwyAoo7ZsLVcW9LWf-72COIJSxv' \
      --data-urlencode 'grant_type=authorization_code' \
      --data-urlencode 'redirect_uri=http://example.com' \
      --data-urlencode 'client_id=belajar'
    ```
   
    Hasilnya seperti ini 
   
    ```json
    {
       "access_token": "eyJraWQiOiJiNjMxY2I5Ny01OGYxLTRjYzItYjA1Ni05NWYzMzY4NmYxZTciLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMDAxIiwiYXVkIjoiYmVsYWphciIsIm5iZiI6MTYxNjY2NzI3OSwiaXNzIjoiaHR0cDpcL1wvMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE2MTY2Njc1NzksImlhdCI6MTYxNjY2NzI3OSwianRpIjoiOWU5ZjljMGUtMDM2Yy00NzgyLWEwNTUtMGUxMGM4MGJjMmNjIn0.heqkNPRs750V0ZeImxALdSsEilavSpq6LuzmcAvP5y_cfees5Pg8zP_hv-dEVtl5SFFhIBemy5otft93jcmjsLBEtesnZHLQIA9MQdEFPc4SUD4OaepcF28tHDQVnogkLZ_hifbe33DvZT3sUAutowgobpu-Zwz27ba3tu7EYVv-UkAZe6LIgKlVCLRYkToWY70ttSDGwHUWRdR2bO9_fYhSUYnXB8fwpaMPIA_MrT2wnuzIwL4ZhTxbG2HNX-qNBehawLS4osQ38jOACRKHioOwA_y4-LgFGIdaY4ZczjBTuWAdgdJy6XFiH6w_NatmuFCUvCzsJwqMZ1k8WCQRVQ",
       "refresh_token": "izgAaCk8Kzcz1pEsLcPC9B4Ov6n3itZljLyghY3v1KZy1FagljD3YShqPIcBV80WJABR_qzULX0u6aaDz6hOg-YTwOBlbCbAGbEnHEF3-amwjdQxnWF0ggsu2lQbiwDX",
       "token_type": "Bearer",
       "expires_in": "299"
    } 
    ```

5. Decode di [JWT.io](https://jwt.io)

    [![JWT.io](./img/jwt-io.png)](./img/jwt-io.png)

## Mendapatkan Access Token dengan Grant Type Resource Owner Password ##

1. Lakukan HTTP Request untuk mendapatkan access token

    ```
    curl --location --request POST 'http://127.0.0.1:9000/oauth2/token' \
      --header 'Authorization: Basic YmVsYWphcjpiZWxhamFyMTIz' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode 'grant_type=password' \
      --data-urlencode 'username=user001' \
      --data-urlencode 'password=teststaff'
    ```

2. Responsenya seperti ini

    ```json
    {
      "error_description": "OAuth 2.0 Parameter: grant_type",
      "error": "unsupported_grant_type",
      "error_uri": "https://tools.ietf.org/html/rfc6749#section-5.2"
    }
    ```
    
    karena di versi `0.1.0` ini grant type `password` belum disupport

## Verifikasi JWT Token ##

1. Ambil informasi public key di `jwks_uri`

    ```
    curl http://127.0.0.1:9000/oauth2/jwks
    ```
    
    Outputnya seperti ini 
   
    ```json
    {
      "keys": [
         {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "b631cb97-58f1-4cc2-b056-95f33686f1e7",
            "n": "j3sw-tGvAkDy-I5FSmUIiDl8bElvJrT71n5AMuzRTWGizgE729ImU2GwxzXvhrglLo0d4EFzKV3qHZFxgcAFh9dxAAOBCahFiIhUTcCZZx4cflcdwQ9kVgTisr4KSuA5A2RjIzFeuRSv3CPTtNVc4BQAAVX6bZJuDg_qVTyojfiblqdc03t1xNhDpfYMM_IYeFU-SUY300c5OjYpKVmTDxoh5C8WxplUrO70EYyq9nQFKprlvY3-258HWk9jrzztkUgODLoBLO60pSgyNjNplW5SKDVIVKJ7s0Z5niNpnbX00RB5GuUBMkv7oRxgBB7FtFeWd9MgeZfCTYHYXYHetw"
         }
      ]
    }
    ```

2. Dapatkan public key dari `JWKS` dengan menggunakan library `jwk-to-pem` yang bisa dijalankan di [https://npm.runkit.com](https://npm.runkit.com).

    Paste kode program berikut di RunKit, jangan lupa ganti variabel `jwk` di baris 2 dengan output dari langkah sebelumnya
   
    ```js
    var jwkToPem = require("jwk-to-pem");
    var jwk = {"kty":"RSA","e":"AQAB","kid":"b631cb97-58f1-4cc2-b056-95f33686f1e7","n":"j3sw-tGvAkDy-I5FSmUIiDl8bElvJrT71n5AMuzRTWGizgE729ImU2GwxzXvhrglLo0d4EFzKV3qHZFxgcAFh9dxAAOBCahFiIhUTcCZZx4cflcdwQ9kVgTisr4KSuA5A2RjIzFeuRSv3CPTtNVc4BQAAVX6bZJuDg_qVTyojfiblqdc03t1xNhDpfYMM_IYeFU-SUY300c5OjYpKVmTDxoh5C8WxplUrO70EYyq9nQFKprlvY3-258HWk9jrzztkUgODLoBLO60pSgyNjNplW5SKDVIVKJ7s0Z5niNpnbX00RB5GuUBMkv7oRxgBB7FtFeWd9MgeZfCTYHYXYHetw"};
    var pem = jwkToPem(jwk);
    console.log(pem);
    ```

    Hasilnya seperti ini

    [![JWT to PEM](./img/jwt-to-pem.png)](./img/jwt-to-pem.png)
   
3. Copy public key yang didapatkan di RunKit

    ```
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj3sw+tGvAkDy+I5FSmUI
    iDl8bElvJrT71n5AMuzRTWGizgE729ImU2GwxzXvhrglLo0d4EFzKV3qHZFxgcAF
    h9dxAAOBCahFiIhUTcCZZx4cflcdwQ9kVgTisr4KSuA5A2RjIzFeuRSv3CPTtNVc
    4BQAAVX6bZJuDg/qVTyojfiblqdc03t1xNhDpfYMM/IYeFU+SUY300c5OjYpKVmT
    Dxoh5C8WxplUrO70EYyq9nQFKprlvY3+258HWk9jrzztkUgODLoBLO60pSgyNjNp
    lW5SKDVIVKJ7s0Z5niNpnbX00RB5GuUBMkv7oRxgBB7FtFeWd9MgeZfCTYHYXYHe
    twIDAQAB
    -----END PUBLIC KEY-----
    ```

4. Paste di `JWT.io` tadi untuk verifikasi signature. Seharusnya hasilnya verified.

    [![JWT Signature Verified](./img/jwt-verified.png)](./img/jwt-verified.png)