const express = require('express');
var bodyParser = require('body-parser');
let supertokens = require('supertokens-node');
let SuperTokensRequest = require('supertokens-website');
let Auth0Client = require('../src/Auth0Client').default;
let verify = require('../src/jwt').verify;
let unfetch = require('unfetch');

const app = express();

supertokens.init({
  hosts: 'https://try.supertokens.io',
  cookieSameSite: 'lax'
});

SuperTokensRequest.init('http://localhost:8080/refresh', 440);
app.use(bodyParser.json());

const mockWindow = global;
const mockFetch = (mockWindow.fetch = unfetch);
const mockVerify = verify;

const setup = (config, claims) => {
  const auth0 = new Auth0Client();
  Object.assign(
    {
      domain: 'auth0_domain',
      client_id: 'auth0_client_id',
      redirect_uri: 'my_callback_url'
    },
    config
  );
  mockVerify.mockReturnValue({
    claims: Object.assign(
      {
        exp: Date.now() / 1000 + 86400
      },
      claims
    )
  });

  return auth0;
};

app.post('/supertokens-auth0', async (req, res, next) => {
  await supertokens.auth0Handler(
    req,
    res,
    next,
    'auth0_domain',
    'auth0_client_id',
    'my_code'
  );
});
