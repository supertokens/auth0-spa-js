import 'fast-text-encoding';
import Auth0Client from '../src/Auth0Client';
import { verify } from '../src/jwt';
import { MessageChannel } from 'worker_threads';
import { Auth0ClientOptions, IdToken } from '../src';
import * as scope from '../src/scope';
import * as utils from '../src/utils';
import {
  expectToHaveBeenCalledWithAuth0ClientParam,
  BASE_URL,
  startST
} from './helpers';
import SuperTokensRequest from 'supertokens-website';
const nodeFetch = require('node-fetch');
const tough = require('tough-cookie');
let cookieStore = new tough.CookieJar(null, false);
const fetchC = require('fetch-cookie')(nodeFetch, cookieStore);
const { spawn } = require('child_process');
let axios = require('axios');

jest.mock('unfetch');
jest.mock('es-cookie');
jest.mock('../src/jwt');
jest.mock('../src/token.worker');

jest.unmock('browser-tabs-lock');

const mockWindow = <any>global;
mockWindow.fetch = fetchC;
const mockVerify = <jest.Mock>verify;

SuperTokensRequest.init({
  refreshTokenUrl: BASE_URL + '/session/refresh'
});

SuperTokensRequest.init({
  refreshTokenUrl: BASE_URL + '/session/refresh'
});
let fetch = (global as any).fetch;

const setup = async (
  config?: Partial<Auth0ClientOptions>,
  claims?: Partial<IdToken>
) => {
  const auth0 = new Auth0Client(
    Object.assign(
      {
        domain: 'auth0_domain',
        client_id: 'auth0_client_id',
        redirect_uri: 'my_callback_url'
      },
      config
    )
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

const login: any = async (
  auth0,
  tokenSuccess = true,
  tokenResponse = {},
  code = 'my_code',
  state = 'MTIz'
) => {
  await fetch(BASE_URL + '/set-mock', {
    method: 'post',
    body: JSON.stringify({ tokenResponse: tokenResponse }),
    headers: { 'Content-Type': 'application/json' }
  });

  await auth0.loginWithRedirect();
  expect(mockWindow.location.assign).toHaveBeenCalled();
  window.history.pushState({}, '', `/?code=${code}&state=${state}`);
  await auth0.handleRedirectCallback();
};

describe('Auth0Client', () => {
  beforeAll(async () => {
    spawn('./test/startServer', [
      process.env.INSTALL_PATH,
      process.env.NODE_PORT === undefined ? 8080 : process.env.NODE_PORT
    ]);
    await new Promise(r => setTimeout(r, 1000));
  });

  afterAll(async function () {
    let instance = axios.create();
    await instance.post(BASE_URL + '/after');
    try {
      await instance.get(BASE_URL + '/stop');
    } catch (err) {}
  });

  beforeEach(async () => {
    await fetch(BASE_URL + '/logout', { method: 'POST' });
    mockWindow.location.assign = jest.fn();
    mockWindow.crypto = {
      subtle: {
        digest: () => 'foo'
      },
      getRandomValues() {
        return '123';
      }
    };
    mockWindow.MessageChannel = MessageChannel;
    mockWindow.Worker = {};
    jest.spyOn(scope, 'getUniqueScopes');
    let instance = axios.create();
    await instance.post(BASE_URL + '/beforeeach');
    await new Promise(r => setTimeout(r, 1000));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should log the user in with custom auth0Client', async () => {
    await startST();
    const auth0Client = { name: '__test_client__', version: '0.0.0' };
    const auth0 = await setup({ auth0Client });
    await login(auth0);
    expectToHaveBeenCalledWithAuth0ClientParam(
      mockWindow.location.assign,
      auth0Client
    );
    expect(await auth0.isAuthenticated()).toBeTruthy();
  });

  it('ensures the openid scope is defined when customizing default scopes', async () => {
    const auth0 = await setup({
      advancedOptions: {
        defaultScope: 'test-scope'
      }
    });
    expect((<any>auth0).defaultScope).toBe('openid test-scope');
  });

  it('allows an empty custom default scope', async () => {
    const auth0 = await setup({
      advancedOptions: {
        defaultScope: null
      }
    });

    expect((<any>auth0).defaultScope).toBe('openid');
  });

  it('should create issuer from domain', async () => {
    const auth0 = await setup({
      domain: 'test.dev'
    });

    expect((<any>auth0).tokenIssuer).toEqual('https://test.dev/');
  });

  it('should allow issuer as a domain', async () => {
    const auth0 = await setup({
      issuer: 'foo.bar.com'
    });

    expect((<any>auth0).tokenIssuer).toEqual('https://foo.bar.com/');
  });

  it('should allow issuer as a fully qualified url', async () => {
    const auth0 = await setup({
      issuer: 'https://some.issuer.com/'
    });

    expect((<any>auth0).tokenIssuer).toEqual('https://some.issuer.com/');
  });

  it('uses the cache when expires_in > constant leeway', async () => {
    await startST();
    const auth0 = await setup();
    await login(auth0, true, { expires_in: 70 });

    jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
      access_token: 'my_access_token',
      state: 'MTIz'
    });

    await auth0.getTokenSilently();
    let response = await fetch(BASE_URL + '/get-refresh-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesSTRefreshCalled).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithCode).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithoutCode).toEqual(0);
  });

  it('refreshes the token when expires_in < constant leeway', async () => {
    await startST();
    const auth0 = await setup();
    await login(auth0, true, { expires_in: 50 });

    jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
      access_token: 'my_access_token',
      state: 'MTIz',
      code: 'my_code'
    });

    await auth0.getTokenSilently();

    let response = await fetch(BASE_URL + '/get-refresh-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesSTRefreshCalled).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithCode).toEqual(1);
    expect(response.noOfTimesAuth0RefreshCalledWithoutCode).toEqual(0);
  });

  it('test that refreshes the token when expires_in < constant leeway & refresh tokens are used', async () => {
    await startST();
    const auth0 = await setup({
      useRefreshTokens: true
    });

    await login(auth0, true, { expires_in: 50 });

    await auth0.getTokenSilently();

    let response = await fetch(BASE_URL + '/get-refresh-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesSTRefreshCalled).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithCode).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithoutCode).toEqual(1);
  });

  it('test that logout action is done when auth0 logout is performed', async () => {
    await startST();
    const auth0 = await setup();

    await login(auth0);

    expect(await auth0.isAuthenticated).toBeTruthy();

    await auth0.logout();

    await new Promise(r => {
      setTimeout(r, 1500);
    });

    let response = await fetch(BASE_URL + '/get-logout-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesLogoutCalled).toEqual(1);
  });

  it('test supertokens session management', async () => {
    await startST();
    const auth0 = await setup();
    await login(auth0);

    let response = await fetch(BASE_URL + '/test-session-management', {
      method: 'POST'
    });

    response = await response.json();
    expect(response.message).toEqual('OK');
  });
});
