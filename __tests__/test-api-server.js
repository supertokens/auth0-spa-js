const express = require('express');
const nock = require('nock');
var bodyParser = require('body-parser');
let supertokens = require('supertokens-node');
const axios = require('axios');

const app = express();

supertokens.init({
  hosts: 'https://try.supertokens.io',
  cookieSameSite: 'lax'
});

app.use(bodyParser.json());

app.post('/supertokens-auth0', async (req, res, next) => {
  nock('https://test.com').post('/oauth/token').reply(200, {
    id_token:
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImM4WXdlNGNIUGFwZElHSm5zYXlLUSJ9.eyJuaWNrbmFtZSI6ImFiYyIsIm5hbWUiOiJhYmNAZ21haWwuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyLzNmMDA5ZDcyNTU5ZjUxZTdlNDU0YjE2ZTVkMDY4N2ExP3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGYWIucG5nIiwidXBkYXRlZF9hdCI6IjIwMjAtMDgtMTdUMDY6Mjk6MjMuOTQxWiIsImVtYWlsIjoiYWJjQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiaXNzIjoiaHR0cHM6Ly9kZXYtM215aTZiM2UudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVmMjFkNzUyZGM2ODI2MDBhMGI2MjZmNiIsImF1ZCI6IndRd2FkTllMNThQb1hEVElFaUxlQm1DZTg5Qm5NZml2IiwiaWF0IjoxNTk3NjQ1NzY1LCJleHAiOjE1OTc2ODE3NjUsIm5vbmNlIjoiTkRkeGNFbGZNblpvTUhwelVVSklUa056T0dGUmRGUmtWbFJCVFdzd1kyMTVhV28wTFdkd1kxaCtNdz09In0.Ufpc3quaELrFwy8CeJsE3e9fby3MDEmQBm16vqwdcbfSqX8P3WLTQ0WOPda06COTP3dfahxLrRMQEjUqrQqnKIm_1nTJvJQiaYf1KJlvo3LnUU3IQ0Q6yMtcB1HomWeOMGJnViRKAhQm3N7tgXTIA9W6W8iyXtX4s5_b2mzVpcP-hwc1YxeF1_lZWQqPOfh0-79RQwQ3vVkr0bFCEvGYIUJ4-_D2egE4d69EPXI1Ih-rypVPhNPTXmpWkKHDKIZFWf7Mme130_Sv1Ynh3ReoCgoI0RpxogHOKaTqYcgvYPlyQlBePALAj23eKfM-Ykwxhmv0USn--W6-w8wxxlr6jw',
    expires_in: 84000,
    access_token: 'access_token',
    refresh_token: 'refresh_token'
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

app.post('/refresh', supertokens.middleware(), (req, res) => {
  res.send('');
});
// app.post("/test", async (req, res) => {
//     nock('http://test.com')
//         .post('/test')
//         .reply(200, {
//             //response
//             message: "OK"
//         });

//     let testResponse = await axios({
//         method: "post",
//         url: `http://test.com/test`,
//     });
//     console.log(testResponse.data)
//     res.send(JSON.stringify(testResponse.data))
// });

app.use(supertokens.errorHandler());

app.listen(3000);
