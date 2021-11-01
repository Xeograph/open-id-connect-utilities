# generate_id_token.py
The `generate_id_token.py` utility is intended for testing purposes only and should NOT be used in any production environment. The utility is a stand in for a Security Token Service integrated within an OpenID Connect provider that can issue ID Tokens for users.

# Dependencies
- python3 (version 3.8.5)
- pip3
- [requests](https://github.com/psf/requests)

To install dependencies run the following command:
    
    pip3 install -r requirements.txt
    
    
# Generating an ID Token
The script implements the [implicit grant flow](https://openid.net/specs/openid-connect-implicit-1_0.html#Overview). The application will initiate an authentication request to an OpenID Connect provider of your choosing. The application will launch a window in the host machine's default web browser application where the user may authenticate directly with the provider. After the user completes authentication, the provider will redirect the user to the local server with the ID token issued the provider. The token will be printed to `stdout`.

In order to run the client, you will need to:
- Configure an OpenID client in the OpenID provider. Make sure to set the redirect URI for the client to `https://localhost:4553/callback` (modify the port if using a custom value).
- Copy the provider's issuer URL (e.g. `https://accounts.google.com`).
- Copy the `client_id` of the application this token is issued for. This should match the `client_id` used to configure the Ocient database.

To run the application, execute:
    
    python3 generate_id_token.py <issuer> <client_id>
    

For example:
    
    python3 generate_id_token.py https://accounts.google.com my-google-client
    

