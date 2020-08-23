/* Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.
 *
 * This software is licensed under the Apache License, Version 2.0 (the
 * "License") as published by the Apache Software Foundation.
 *
 * You may not use this file except in compliance with the License. You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
let supertokens = require('supertokens-node');
let express = require('express');
let cookieParser = require('cookie-parser');
let bodyParser = require('body-parser');
let http = require('http');
let {
  startST,
  stopST,
  killAllST,
  setupST,
  cleanST,
  setKeyValueInConfig
} = require('./utils');
var cors = require('cors');
let urlencodedParser = bodyParser.urlencoded({
  limit: '20mb',
  extended: true,
  parameterLimit: 20000
});
let jsonParser = bodyParser.json({ limit: '20mb' });
const nock = require('nock');

let app = express();
app.use(urlencodedParser);
app.use(jsonParser);
app.use(cookieParser());
app.use(cors());

supertokens.init({
  hosts: 'http://localhost:9000'
});

let tokenResponse = {};
let noOfTimesAuth0RefreshCalledWithCode = 0;
let noOfTimesAuth0RefreshCalledWithoutCode = 0;
let noOfTimesSTRefreshCalled = 0;
let noOfTimesLogoutCalled = 0;

app.post('/supertokens-auth0', async (req, res, next) => {
  let body = req.body;
  if (body.action == 'refresh') {
    body.code !== undefined
      ? noOfTimesAuth0RefreshCalledWithCode++
      : noOfTimesAuth0RefreshCalledWithoutCode++;
  } else if (body.action == 'logout') {
    noOfTimesLogoutCalled++;
  }

  nock('https://test.com')
    .post('/oauth/token')
    .reply(200, {
      id_token:
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImM4WXdlNGNIUGFwZElHSm5zYXlLUSJ9.eyJuaWNrbmFtZSI6ImFiYyIsIm5hbWUiOiJhYmNAZ21haWwuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyLzNmMDA5ZDcyNTU5ZjUxZTdlNDU0YjE2ZTVkMDY4N2ExP3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGYWIucG5nIiwidXBkYXRlZF9hdCI6IjIwMjAtMDgtMTdUMDY6Mjk6MjMuOTQxWiIsImVtYWlsIjoiYWJjQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaXNzIjoiaHR0cHM6Ly9kZXYtM215aTZiM2UudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVmMjFkNzUyZGM2ODI2MDBhMGI2MjZmNiIsImF1ZCI6IndRd2FkTllMNThQb1hEVElFaUxlQm1DZTg5Qm5NZml2IiwiaWF0IjoxNTk3NjQ1NzY1LCJleHAiOjE1OTc2ODE3NjUsIm5vbmNlIjoiTkRkeGNFbGZNblpvTUhwelVVSklUa056T0dGUmRGUmtWbFJCVFdzd1kyMTVhV28wTFdkd1kxaCtNdz09In0.Ufpc3quaELrFwy8CeJsE3e9fby3MDEmQBm16vqwdcbfSqX8P3WLTQ0WOPda06COTP3dfahxLrRMQEjUqrQqnKIm_1nTJvJQiaYf1KJlvo3LnUU3IQ0Q6yMtcB1HomWeOMGJnViRKAhQm3N7tgXTIA9W6W8iyXtX4s5_b2mzVpcP-hwc1YxeF1_lZWQqPOfh0-79RQwQ3vVkr0bFCEvGYIUJ4-_D2egE4d69EPXI1Ih-rypVPhNPTXmpWkKHDKIZFWf7Mme130_Sv1Ynh3ReoCgoI0RpxogHOKaTqYcgvYPlyQlBePALAj23eKfM-Ykwxhmv0USn--W6-w8wxxlr6jw',
      expires_in: 84000,
      access_token: 'access_token',
      refresh_token: 'refresh_token',
      ...tokenResponse
    });
  await supertokens.auth0Handler(
    req,
    res,
    next,
    'test.com',
    'auth0_client_id',
    'my_code'
  );
});

app.post('/set-mock', async (req, res, next) => {
  tokenResponse = req.body.tokenResponse;
  res.send('');
});

app.post('/session/refresh', supertokens.middleware(), (req, res) => {
  noOfTimesSTRefreshCalled++;
  res.send('');
});

app.get('/get-refresh-count', (req, res) => {
  res.send({
    noOfTimesSTRefreshCalled,
    noOfTimesAuth0RefreshCalledWithCode,
    noOfTimesAuth0RefreshCalledWithoutCode
  });
});

app.get('/get-logout-count', (req, res) => {
  res.send({
    noOfTimesLogoutCalled
  });
});

app.post(
  '/test-session-management',
  supertokens.middleware(),
  async (req, res) => {
    //get session
    let session = req.session;
    let sessionData = await session.getSessionData();

    if (sessionData.refresh_token !== 'refresh_token') {
      throw new Error('Incorrect refresh token');
    }

    await session.revokeSession();
    res.send({ message: 'OK' });
  }
);

app.post('/logout', supertokens.middleware(), async (req, res) => {
  await req.session.revokeSession();
  res.send('');
});

app.post('/startst', async (req, res) => {
  let accessTokenValidity =
    req.body.accessTokenValidity === undefined
      ? 1
      : req.body.accessTokenValidity;
  let enableAntiCsrf =
    req.body.enableAntiCsrf === undefined ? true : req.body.enableAntiCsrf;
  await setKeyValueInConfig('access_token_validity', accessTokenValidity);
  await setKeyValueInConfig('enable_anti_csrf', enableAntiCsrf);
  let pid = await startST();
  res.send(pid + '');
});

app.post('/beforeeach', async (req, res) => {
  tokenResponse = {};
  noOfTimesSTRefreshCalled = 0;
  noOfTimesAuth0RefreshCalledWithCode = 0;
  noOfTimesAuth0RefreshCalledWithoutCode = 0;
  noOfTimesLogoutCalled = 0;
  res.send('');
  await killAllST();
  await setupST();
  await setKeyValueInConfig('cookie_secure', 'false');
  res.send();
});

app.post('/after', async (req, res) => {
  await killAllST();
  await cleanST();
  res.send();
});

app.post('/stopst', async (req, res) => {
  await stopST(req.body.pid);
  res.send('');
});

app.get('/stop', async (req, res) => {
  process.exit();
});

app.use('*', async (req, res, next) => {
  res.status(404).send();
});

app.use(supertokens.errorHandler());

app.use(async (err, req, res, next) => {
  res.send(500).send(err);
});

let server = http.createServer(app);
server.listen(
  process.env.NODE_PORT === undefined ? 8080 : process.env.NODE_PORT,
  '0.0.0.0'
);
