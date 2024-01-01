//! # token_adalt
//!
//! A utility library for acquiring tokens from Active Directory.
//!
//! Authentication can be one of
//! * [Client certificate based authentication](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials)
//!   The library supports both [x5c](https://tools.ietf.org/html/rfc7515#section-4.1.6) and [x5t](https://tools.ietf.org/html/rfc7515#section-4.1.7)
//! * [Client secret based authentication](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)


extern crate openssl;
extern crate serde_json;
extern crate uuid;
extern crate reqwest;

pub mod adalt {
    use std::io::Read;
    use serde_json::json;
    use openssl::x509::X509;
    use uuid::Uuid;
    use std::time::{SystemTime, Duration};
    use serde_json::Value;
    use std::error::Error;
    use std::fmt;
    use std::str::FromStr;

    /// Client Credentials are either based on secret or cert-based.
    /// For certificate based auth -- path to the `pfx` file, password of the certificate and a boolean indicating whether to use x5c or x5t for JWT.
    #[derive(Debug)]
    pub enum Credentials {
        Pkcs12 {path:String, password:String, x5c:bool},
        Secret(String)
    }

    /// Token returned from AD.
    #[derive(Debug, Clone)]
    pub struct Token{
        pub token:String,
        pub token_type: String,
        pub expiry: SystemTime
    }

    /// Authorization Context to be used for acquiring token.
    pub struct Context{
        tenant_id: String,
        client_id: String,
        resource: String,
        credentials:Credentials,
        token:Option<Token>,
        client:reqwest::Client
    }

    /// Error in authentication
    #[derive(Debug)]
    pub struct AuthenticationError {
        info: String,
    }

    impl fmt::Display for AuthenticationError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.info)
        }
    }

    impl Error for AuthenticationError {}
    
    impl Context {
        pub fn new(tenant:&str, client:&str, resource:&str, credentials:Credentials) -> Context {
            Context {
                tenant_id: String::from(tenant),
                client_id: String::from(client),
                resource: String::from(resource),
                credentials: credentials,
                token: None,
                client: reqwest::Client::new()
            }
        }

        /// method just to get the jwt
        fn jwt(&self) -> Result<String, AuthenticationError> {
            match &self.credentials {
                Credentials::Pkcs12 {path:p, password:pss, x5c:is_x5c} => extract_jwt(&p, &pss, &self.tenant_id, &self.client_id, *is_x5c),
                _  =>  Err(AuthenticationError { info: "internal error: jwt is relevent only for pfx".to_string()})
            }
        }

        /// asynchronous method to acquire token. If the token's expiration is _sufficiently_ in future, the same is reused.
        /// # Example
        /// ```
        /// let tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        /// let client_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        /// let cert_location = "/path/to/cert/file/abcdefghijklmnopqrstuvw.xyz";
        /// let cert_password = "*********";
        /// let creds = adalt::Credentials::Pkcs12 { path: String::from(cert_location), password: String::from(cert_password), x5c:false };
        /// let resource = "https://resource.blah.com";
        /// let mut ctx = adalt::Context::new(tenant_id, client_id, resource, creds);
        ///  let future = ctx.get_token().await?;
        /// ```
        pub async fn get_token(&mut self) -> Result<Token, AuthenticationError> {
            match &self.token {
                Some(t) => {
                    let now = SystemTime::now();
                    let difference = &t.expiry.duration_since(now);
                    let reuse = match difference {
                        Ok(d) => d.as_secs() > 1800,
                        _ => false
                    };
                    if reuse {
                        return Ok(t.clone());
                    }
                }
                _ => {
                }
            }

            let response = match &self.credentials {
                Credentials::Pkcs12{path:_, password:_, x5c:_} => get_cert_token(&self).await?,
                Credentials::Secret(_)    =>  get_secret_token(&self).await?
            };

            let v: Value = serde_json::from_str(&response).expect("response from AD is not a valid json");
            let token_type = match v["token_type"].as_str() {
                Some(t) => String::from(t),
                None => String::from("Bearer")
            };
            
            let expiry = match v["expires_in"].as_str() {
                Some(t) => match u64::from_str(t) {
                    Ok(v) => {
                        let now = SystemTime::now();
                        let d = Duration::from_secs(v);
                        match now.checked_add(d) {
                            Some(e) => e,
                            None => now
                        }
                    },
                    _ => SystemTime::now()
                },
                None => SystemTime::now()
            };

            let token = match v["access_token"].as_str() {
                Some(t) => String::from(t),
                None => {
                    return Err(AuthenticationError { info: "failed to authenticate".to_string()});
                }
            };
            let token = Token {token_type, token, expiry};
            self.token = Some(token.clone());
            Ok(token)
        }
    }

    fn base64_url(src: Vec<u8>) -> String {
        let base64 = openssl::base64::encode_block(&src);
        let mut result = String::new();
        for c in base64.chars() {
            if c == '+' {
                result.push('-');
            }
            else if c == '/' {
                result.push('_');
            }
            else if c != '=' && c != '\r' && c != '\n' {
                result.push(c);
            }
        }
        result
    }

    fn header_x5t(x509: &X509) -> String {
        let sha1 = openssl::hash::MessageDigest::sha1();
        let digest = x509.digest(sha1).expect("could not get the digest");
        let digest = openssl::base64::encode_block(&digest);
        let x5t_header = json!({"alg": "RS256", "typ" : "JWT", "x5t": digest});
        let header = base64_url(x5t_header.to_string().into_bytes());
        header
    }

    fn header_x5c(x509: &X509) -> String {
        let sha1 = openssl::hash::MessageDigest::sha1();
        let digest = x509.digest(sha1).expect("could not get the digest");
        let digest = openssl::base64::encode_block(&digest);
        let der = x509.to_der().expect("failed to get der data");
        let der = openssl::base64::encode_block(&der);
        let x5c_header = json!({"alg": "RS256", "typ" : "JWT", "kid": digest, "x5c": der});
        let header = base64_url(x5c_header.to_string().into_bytes());
        header
    }

    fn payload(tenant_id: &str, client_id: &str) -> String {
        let audience = format!("https://login.microsoftonline.com/{}/oauth2/token", tenant_id);
        let jti = Uuid::new_v4();
        let jti = format!("{}", jti);
        let nbf = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let exp = nbf + 3600;
        let pl = json!({"aud" : audience, "exp" : exp, "iss" : client_id, "jti" : jti, "nbf" : nbf, "sub" : client_id});
        let pl = pl.to_string().into_bytes();
        base64_url(pl)
    }
    
    fn extract_jwt(file_name: &str, password: &str, tenant_id: &str, client_id: &str, is_x5c:bool) -> Result<String, AuthenticationError> {
        let mut f = std::fs::File::open(file_name).expect("file not found");
        let mut pfx_contents = Vec::new();
        f.read_to_end(&mut pfx_contents).expect("failed to read contents");
        let pfx = openssl::pkcs12::Pkcs12::from_der(&pfx_contents).expect("could not read from der");
        let parsed_pfx = pfx.parse2(password).expect("could not parse");
        if parsed_pfx.cert.is_none() || parsed_pfx.pkey.is_none() {
            return Err(AuthenticationError { info: "unable to read cert or key from the pfx file".to_string()});
        }
        let cert = parsed_pfx.cert.unwrap();
        let pkey = parsed_pfx.pkey.unwrap();
        let header = if is_x5c {
            header_x5c(&cert)
        } else {
            header_x5t(&cert)
        };
  
        let jws = format!("{}.{}", header,payload(tenant_id, client_id));
        let jws_bytes = jws.clone().into_bytes();
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
        signer.update(&jws_bytes).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let signature = openssl::base64::encode_block(&signature);
        
        Ok(format!("{}.{}", jws, signature))
    }

    async fn get_secret_token(context: &Context) -> Result<String, AuthenticationError> {
        let secret = match &context.credentials {
            Credentials::Secret(s) => s.to_string(),
            _ => panic!("invalid credentials for secret")
        };
        
        let url = format!("https://login.microsoftonline.com/{}/oauth2/token", context.tenant_id);
        let params = [("resource", context.resource.clone()),
                      ("client_id", context.client_id.clone()),
                      ("client_secret", secret),
                      ("grant_type","client_credentials".to_string())];
        let res = context.client.post(&url).form(&params).send().await;
        if let Err(r) = res {
            return Err(AuthenticationError { info: r.to_string() });
        }
        let body = res.unwrap().text().await;
        if let Err(r) = body {
            return Err(AuthenticationError {info : r.to_string()});
        }
        Ok(body.unwrap())
    }

    
    async fn get_cert_token(context: &Context) -> Result<String, AuthenticationError> {
        let jwt = context.jwt()?;
        let url = format!("https://login.microsoftonline.com/{}/oauth2/token", context.tenant_id);
        let params = [("resource", context.resource.clone()),
                      ("client_id", context.client_id.clone()),
                      ("client_assertion_type","urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()),
                      ("client_assertion", jwt),
                      ("grant_type","client_credentials".to_string())];
        let res = context.client.post(&url).form(&params).send().await;
        if let Err(x) = res {
            return Err(AuthenticationError { info: x.to_string() });
        }
        let body = res.unwrap().text().await;
        if let Err(x) = body {
            return Err(AuthenticationError{ info: x.to_string()});
        }
        Ok(body.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn x5t_works() {
        let tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        let client_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        let cert_location = "abcdefghijklmnopqrstuvw.xyz";
        let cert_password = "*********";
        let creds = adalt::Credentials::Pkcs12 { path: String::from(cert_location), password: String::from(cert_password), x5c:false };
        let resource = "https://resource.blah.com";
        
        let mut ctx = adalt::Context::new(tenant_id, client_id, resource, creds);
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        
        let future = ctx.get_token();
        match rt.block_on(future) {
            Ok(token) => println!("token = {:#?}", token),
            Err(e) => panic!("An error occured: {}", e)
        }
        let future = ctx.get_token();
        match rt.block_on(future) {
            Ok(token) => println!("token = {:#?}", token),
            Err(e) => panic!("An error occured: {}", e)
        }

    }

    #[test]
    fn x5c_works() {
        let tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        let client_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        let cert_location = "abcdefghijklmnopqrstuvw.xyz";
        let cert_password = "*********";
        let creds = adalt::Credentials::Pkcs12 { path: String::from(cert_location), password: String::from(cert_password), x5c:true };
        let resource = "https://resource.blah.com";

        let mut ctx = adalt::Context::new(tenant_id, client_id, resource, creds);
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        
        let future = ctx.get_token();
        match rt.block_on(future) {
            Ok(token) => println!("token = {:#?}", token),
            Err(e) => panic!("An error occured: {}", e)
        }
        let future = ctx.get_token();
        match rt.block_on(future) {
            Ok(token) => println!("token = {:#?}", token),
            Err(e) => panic!("An error occured: {}", e)
        }

    }
}
