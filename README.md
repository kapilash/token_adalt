# token_adalt
(Unofficial and temporary) Rust library that enables you to acquire security token from Azure Active Directory.

## Supported Credentials

* [Client certificate based authentication](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials)
  The library supports both x5c and x5t
* [Client secret based authentication](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)

## Sample

```
  let tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
  let client_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
  let cert_location = "abcdefghijklmnopqrstuvw.xyz";
  let cert_password = "*********";
  let resource = "https://resource.blah.com";
  
  // Create credentials
  let creds = adalt::Credentials::Pkcs12 { path: String::from(cert_location), password: String::from(cert_password), x5c:true };
  
  
  
  
  // create the session
  let mut ctx = adalt::Context::new(tenant_id, client_id, resource, creds);

  // token can be acquired via the future
  let token = ctx.get_token().await?;
```



## Dependencies
Library uses
1. [reqwest](https://crates.io/crates/reqwest) for the calls to Active Directory
2. [openssl](https://crates.io/crates/openssl) for reading certificates
3. [serde](https://crates.io/crates/serde_json) for creating jwt
4. [uuid](https://crates.io/crates/uuid)
