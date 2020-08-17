# supertokens-auth0-spa-js

SuperTokens SDK for Auth0 integration. We improve upon Auth0's integration by using Authorization code grant flow via the backend channel. We keep Auth0's tokens on the backend, and only send SuperTokens' tokens to the frontend via `httpOnly` cookies. We use rotating refresh tokens to maintin a session.

Please refer to @auth0/auth0-spa-js's documentation since the interface is almost the same. A few exceptions are:
- You no longer need to use cognito's access token on the frontend
- You no longer need to take care of refreshing the session manually (if you are doing so)
