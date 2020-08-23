import 'fast-text-encoding';
import * as esCookie from 'es-cookie';
import Auth0Client from '../src/Auth0Client';
import unfetch from 'unfetch';
import { verify } from '../src/jwt';
import { MessageChannel } from 'worker_threads';
import * as utils from '../src/utils';
import { Auth0ClientOptions, IdToken } from '../src';
import * as scope from '../src/scope';
import { expectToHaveBeenCalledWithAuth0ClientParam } from './helpers';
import SuperTokensRequest from 'supertokens-website';
import { resolve } from 'url';
const nodeFetch = require('node-fetch');
const tough = require('tough-cookie');
const fetch = require('fetch-cookie')(
  nodeFetch,
  new tough.CookieJar(null, false)
);

jest.mock('unfetch');
jest.mock('es-cookie');
jest.mock('../src/jwt');
jest.mock('../src/token.worker');

jest.unmock('browser-tabs-lock');

let mockCookie = {
  value_: '',
  get cookie() {
    return this.value_;
  },
  set cookie(value) {
    this.value_ += value + ';';
  }
};

const mockWindow = <any>global;
mockWindow.fetch = fetch;
const mockVerify = <jest.Mock>verify;

const assertUrlEquals = (actualUrl, host, path, queryParams) => {
  const url = new URL(actualUrl);
  expect(url.host).toEqual(host);
  expect(url.pathname).toEqual(path);
  for (let [key, value] of Object.entries(queryParams)) {
    expect(url.searchParams.get(key)).toEqual(value);
  }
};

const assertPost = (url, body, callNum = 0) => {
  const [actualUrl, opts] = mockWindow.fetch.mock.calls[callNum];
  expect(url).toEqual(actualUrl);
  expect(body).toEqual(JSON.parse(opts.body));
};

const fetchResponse = (ok, json) =>
  Promise.resolve({
    ok,
    json: () => Promise.resolve(json)
  });

const setup = async (
  config?: Partial<Auth0ClientOptions>,
  claims?: Partial<IdToken>
) => {
  await fetch('http://localhost:3000/reset', { method: 'POST' });
  SuperTokensRequest.init({
    refreshTokenUrl: 'http://localhost:3000/refresh',
    sessionExpiredStatusCode: 440
  });
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
  await fetch('http://localhost:3000/set-mock', {
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
  beforeEach(() => {
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
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should log the user in with custom auth0Client', async () => {
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
    const auth0 = await setup();
    await login(auth0, true, { expires_in: 70 });

    jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
      access_token: 'my_access_token',
      state: 'MTIz'
    });

    await auth0.getTokenSilently();
    let response = await fetch('http://localhost:3000/get-refresh-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesSTRefreshCalled).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithCode).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithoutCode).toEqual(0);
  });

  it('refreshes the token when expires_in < constant leeway', async () => {
    const auth0 = await setup();
    await login(auth0, true, { expires_in: 50 });

    jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
      access_token: 'my_access_token',
      state: 'MTIz',
      code: 'my_code'
    });

    await auth0.getTokenSilently();

    let response = await fetch('http://localhost:3000/get-refresh-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesSTRefreshCalled).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithCode).toEqual(1);
    expect(response.noOfTimesAuth0RefreshCalledWithoutCode).toEqual(0);
  });

  it('test that refreshes the token when expires_in < constant leeway & refresh tokens are used', async () => {
    const auth0 = await setup({
      useRefreshTokens: true
    });

    await login(auth0, true, { expires_in: 50 });

    await auth0.getTokenSilently();

    let response = await fetch('http://localhost:3000/get-refresh-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesSTRefreshCalled).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithCode).toEqual(0);
    expect(response.noOfTimesAuth0RefreshCalledWithoutCode).toEqual(1);
  });

  it('test that logout action is done when auth0 logout is performed', async () => {
    const auth0 = await setup();

    await login(auth0);

    expect(await auth0.isAuthenticated).toBeTruthy();

    await auth0.logout();

    let response = await fetch('http://localhost:3000/get-logout-count', {
      method: 'GET'
    }).then(res => res.json());

    expect(response.noOfTimesLogoutCalled).toEqual(1);
  });

  it('test supertokens session management', async () => {
    const auth0 = await setup();
    await login(auth0);

    let response = await fetch(
      'http://localhost:3000/test-session-management',
      { method: 'POST' }
    ).then(res => res.json());

    expect(response.message).toEqual('OK');
  });

  // it('automatically adds the offline_access scope during construction', () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     scope: 'test-scope'
  //   });

  //   expect((<any>auth0).scope).toBe('test-scope offline_access');
  // });

  // it("skips checking the auth0 session when there's no auth cookie", async () => {
  //   const auth0 = await setup();

  //   jest.spyOn(<any>utils, 'runIframe');

  //   await auth0.checkSession();

  //   expect(utils.runIframe).not.toHaveBeenCalled();
  // });

  // it("test session when sending an expired token", async () => {
  //   const auth0 = await setup();
  //   await login(auth0);

  //   let response = await fetch('http://localhost:3000/test-session-management', { method: 'POST' })
  //     .then(res => res.json())

  //   expect(response.message).toEqual("OK")

  // });

  // it('should log the user in and get the token', async () => {
  //   const auth0 = await setup();
  //   await login(auth0);
  //   const url = new URL(mockWindow.location.assign.mock.calls[0][0]);
  //   assertUrlEquals(url, 'auth0_domain', '/authorize', {
  //     client_id: 'auth0_client_id',
  //     redirect_uri: 'my_callback_url',
  //     scope: 'openid profile email',
  //     response_type: 'code',
  //     response_mode: 'query',
  //     state: 'MTIz',
  //     nonce: 'MTIz',
  //   });
  //   assertPost('https://auth0_domain/oauth/token', {
  //     redirect_uri: 'my_callback_url',
  //     client_id: 'auth0_client_id',
  //     code_verifier: '123',
  //     grant_type: 'authorization_code',
  //     code: 'my_code'
  //   });
  // });

  // it('refreshes the token from a web worker', async () => {
  //   const auth0 = await setup({
  //     useRefreshTokens: true
  //   });

  //   expect((<any>auth0).worker).toBeDefined();

  //   await login(auth0);

  // mockFetch.mockResolvedValueOnce(
  //   fetchResponse(true, {
  //     id_token: 'my_id_token',
  //     refresh_token: 'my_refresh_token',
  //     access_token: 'my_access_token',
  //     expires_in: 86400
  //   })
  // );

  // const access_token = await auth0.getTokenSilently({ ignoreCache: true });

  // assertPost(
  //   'https://auth0_domain/oauth/token',
  //   {
  //     client_id: 'auth0_client_id',
  //     grant_type: 'refresh_token',
  //     redirect_uri: 'my_callback_url',
  //     refresh_token: 'my_refresh_token'
  //   },
  //   1
  // );

  // expect(access_token).toEqual('my_access_token');
  // });

  // it('refreshes the token without the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     cacheLocation: 'localstorage'
  //   });

  //   expect((<any>auth0).worker).toBeUndefined();

  //   await login(auth0);

  //   assertPost('https://auth0_domain/oauth/token', {
  //     redirect_uri: 'my_callback_url',
  //     client_id: 'auth0_client_id',
  //     code_verifier: '123',
  //     grant_type: 'authorization_code',
  //     code: 'my_code'
  //   });

  //   mockFetch.mockResolvedValueOnce(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );

  //   const access_token = await auth0.getTokenSilently({ ignoreCache: true });

  //   assertPost(
  //     'https://auth0_domain/oauth/token',
  //     {
  //       client_id: 'auth0_client_id',
  //       grant_type: 'refresh_token',
  //       redirect_uri: 'my_callback_url',
  //       refresh_token: 'my_refresh_token'
  //     },
  //     1
  //   );

  //   expect(access_token).toEqual('my_access_token');
  // });

  // it('refreshes the token without the worker, when window.Worker is undefined', async () => {
  //   mockWindow.Worker = undefined;

  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     cacheLocation: 'memory'
  //   });

  //   expect((<any>auth0).worker).toBeUndefined();

  //   await login(auth0);

  //   assertPost('https://auth0_domain/oauth/token', {
  //     redirect_uri: 'my_callback_url',
  //     client_id: 'auth0_client_id',
  //     code_verifier: '123',
  //     grant_type: 'authorization_code',
  //     code: 'my_code'
  //   });

  //   mockFetch.mockResolvedValueOnce(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );

  //   const access_token = await auth0.getTokenSilently({ ignoreCache: true });

  //   assertPost(
  //     'https://auth0_domain/oauth/token',
  //     {
  //       client_id: 'auth0_client_id',
  //       grant_type: 'refresh_token',
  //       redirect_uri: 'my_callback_url',
  //       refresh_token: 'my_refresh_token'
  //     },
  //     1
  //   );

  //   expect(access_token).toEqual('my_access_token');
  // });

  // it('handles fetch errors from the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true
  //   });

  //   expect((<any>auth0).worker).toBeDefined();
  //   await login(auth0);
  //   mockFetch.mockReset();
  //   mockFetch.mockImplementation(() => Promise.reject(new Error('my_error')));
  //   await expect(auth0.getTokenSilently({ ignoreCache: true })).rejects.toThrow(
  //     'my_error'
  //   );
  //   expect(mockFetch).toBeCalledTimes(3);
  // });

  // it('handles api errors from the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true
  //   });
  //   expect((<any>auth0).worker).toBeDefined();
  //   await login(auth0);
  //   mockFetch.mockReset();
  //   mockFetch.mockResolvedValue(
  //     fetchResponse(false, {
  //       error: 'my_api_error',
  //       error_description: 'my_error_description'
  //     })
  //   );
  //   await expect(auth0.getTokenSilently({ ignoreCache: true })).rejects.toThrow(
  //     'my_error_description'
  //   );
  //   expect(mockFetch).toBeCalledTimes(1);
  // });

  // it('handles timeout errors from the worker', async () => {
  //   const constants = require('../src/constants');
  //   const originalDefaultFetchTimeoutMs = constants.DEFAULT_FETCH_TIMEOUT_MS;
  //   Object.defineProperty(constants, 'DEFAULT_FETCH_TIMEOUT_MS', {
  //     get: () => 100
  //   });
  //   const auth0 = setup({
  //     useRefreshTokens: true
  //   });

  //   expect((<any>auth0).worker).toBeDefined();

  //   await login(auth0);
  //   mockFetch.mockReset();
  //   mockFetch.mockImplementation(
  //     () =>
  //       new Promise(resolve =>
  //         setTimeout(
  //           () =>
  //             resolve({
  //               ok: true,
  //               json: () => Promise.resolve({ access_token: 'access-token' })
  //             }),
  //           500
  //         )
  //       )
  //   );
  //   jest.spyOn(AbortController.prototype, 'abort');
  //   await expect(auth0.getTokenSilently({ ignoreCache: true })).rejects.toThrow(
  //     `Timeout when executing 'fetch'`
  //   );
  //   // Called thrice for the refresh token grant in utils (noop)
  //   // Called thrice for the refresh token grant in token worker
  //   expect(AbortController.prototype.abort).toBeCalledTimes(6);
  //   expect(mockFetch).toBeCalledTimes(3);
  //   Object.defineProperty(constants, 'DEFAULT_FETCH_TIMEOUT_MS', {
  //     get: () => originalDefaultFetchTimeoutMs
  //   });
  // });

  // it('falls back to iframe when missing refresh token errors from the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true
  //   });
  //   expect((<any>auth0).worker).toBeDefined();
  //   await login(auth0, true, { refresh_token: '' });
  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });
  //   mockFetch.mockResolvedValueOnce(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );
  //   const access_token = await auth0.getTokenSilently({ ignoreCache: true });
  //   expect(access_token).toEqual('my_access_token');
  //   expect(utils.runIframe).toHaveBeenCalled();
  // });

  // it('handles fetch errors without the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     cacheLocation: 'localstorage'
  //   });
  //   expect((<any>auth0).worker).toBeUndefined();
  //   await login(auth0);
  //   mockFetch.mockReset();
  //   mockFetch.mockImplementation(() => Promise.reject(new Error('my_error')));
  //   await expect(auth0.getTokenSilently({ ignoreCache: true })).rejects.toThrow(
  //     'my_error'
  //   );
  //   expect(mockFetch).toBeCalledTimes(3);
  // });

  // it('handles api errors without the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     cacheLocation: 'localstorage'
  //   });
  //   expect((<any>auth0).worker).toBeUndefined();
  //   await login(auth0);
  //   mockFetch.mockReset();
  //   mockFetch.mockResolvedValue(
  //     fetchResponse(false, {
  //       error: 'my_api_error',
  //       error_description: 'my_error_description'
  //     })
  //   );
  //   await expect(auth0.getTokenSilently({ ignoreCache: true })).rejects.toThrow(
  //     'my_error_description'
  //   );
  //   expect(mockFetch).toBeCalledTimes(1);
  // });

  // it('handles timeout errors without the worker', async () => {
  //   const constants = require('../src/constants');
  //   const originalDefaultFetchTimeoutMs = constants.DEFAULT_FETCH_TIMEOUT_MS;
  //   Object.defineProperty(constants, 'DEFAULT_FETCH_TIMEOUT_MS', {
  //     get: () => 100
  //   });
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     cacheLocation: 'localstorage'
  //   });
  //   expect((<any>auth0).worker).toBeUndefined();
  //   await login(auth0);
  //   mockFetch.mockReset();
  //   mockFetch.mockImplementation(
  //     () =>
  //       new Promise(resolve =>
  //         setTimeout(
  //           () =>
  //             resolve({
  //               ok: true,
  //               json: () => Promise.resolve({ access_token: 'access-token' })
  //             }),
  //           500
  //         )
  //       )
  //   );
  //   jest.spyOn(AbortController.prototype, 'abort');
  //   await expect(auth0.getTokenSilently({ ignoreCache: true })).rejects.toThrow(
  //     `Timeout when executing 'fetch'`
  //   );
  //   // Called thrice for the refresh token grant in utils
  //   expect(AbortController.prototype.abort).toBeCalledTimes(3);
  //   expect(mockFetch).toBeCalledTimes(3);
  //   Object.defineProperty(constants, 'DEFAULT_FETCH_TIMEOUT_MS', {
  //     get: () => originalDefaultFetchTimeoutMs
  //   });
  // });

  // it('falls back to iframe when missing refresh token without the worker', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     cacheLocation: 'localstorage'
  //   });
  //   expect((<any>auth0).worker).toBeUndefined();
  //   await login(auth0, true, { refresh_token: '' });
  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });
  //   mockFetch.mockResolvedValueOnce(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );
  //   const access_token = await auth0.getTokenSilently({ ignoreCache: true });
  //   expect(access_token).toEqual('my_access_token');
  //   expect(utils.runIframe).toHaveBeenCalled();
  // });

  // it('falls back to iframe when missing refresh token in ie11', async () => {
  //   const originalUserAgent = window.navigator.userAgent;
  //   Object.defineProperty(window.navigator, 'userAgent', {
  //     value:
  //       'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
  //     configurable: true
  //   });
  //   const auth0 = setup({
  //     useRefreshTokens: true
  //   });
  //   expect((<any>auth0).worker).toBeUndefined();
  //   await login(auth0, true, { refresh_token: '' });
  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });
  //   mockFetch.mockResolvedValueOnce(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );
  //   const access_token = await auth0.getTokenSilently({ ignoreCache: true });
  //   expect(access_token).toEqual('my_access_token');
  //   expect(utils.runIframe).toHaveBeenCalled();
  //   Object.defineProperty(window.navigator, 'userAgent', {
  //     value: originalUserAgent
  //   });
  // });

  // it('uses the cache for subsequent requests that occur before the response', async () => {
  //   const auth0 = setup();
  //   await login(auth0);
  //   (auth0 as any).cache.clear();
  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });
  //   mockFetch.mockResolvedValue(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );
  //   let [access_token] = await Promise.all([
  //     auth0.getTokenSilently(),
  //     auth0.getTokenSilently(),
  //     auth0.getTokenSilently()
  //   ]);
  //   expect(access_token).toEqual('my_access_token');
  //   expect(utils.runIframe).toHaveBeenCalledTimes(1);
  // });

  // it('uses the cache for multiple token requests with audience and scope', async () => {
  //   const auth0 = setup();
  //   await login(auth0);
  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });
  //   mockFetch.mockResolvedValue(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );
  //   let access_token = await auth0.getTokenSilently({
  //     audience: 'foo',
  //     scope: 'bar'
  //   });
  //   expect(access_token).toEqual('my_access_token');
  //   expect(utils.runIframe).toHaveBeenCalledTimes(1);
  //   (<jest.Mock>utils.runIframe).mockClear();
  //   access_token = await auth0.getTokenSilently({
  //     audience: 'foo',
  //     scope: 'bar'
  //   });
  //   expect(access_token).toEqual('my_access_token');
  //   expect(utils.runIframe).not.toHaveBeenCalled();
  // });

  // it('sends custom options through to the token endpoint when using an iframe', async () => {
  //   const auth0 = setup({
  //     custom_param: 'foo',
  //     another_custom_param: 'bar'
  //   });

  //   await login(auth0, true);

  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });

  //   mockFetch.mockResolvedValue(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );

  //   await auth0.getTokenSilently({
  //     ignoreCache: true,
  //     custom_param: 'hello world'
  //   });

  //   expect(
  //     (<any>utils.runIframe).mock.calls[0][0].includes(
  //       'custom_param=hello%20world&another_custom_param=bar'
  //     )
  //   ).toBe(true);

  //   expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
  //     redirect_uri: 'my_callback_url',
  //     client_id: 'auth0_client_id',
  //     grant_type: 'authorization_code',
  //     custom_param: 'hello world',
  //     another_custom_param: 'bar',
  //     code_verifier: '123'
  //   });
  // });

  // it('sends custom options through to the token endpoint when using refresh tokens', async () => {
  //   const auth0 = setup({
  //     useRefreshTokens: true,
  //     custom_param: 'foo',
  //     another_custom_param: 'bar'
  //   });

  //   await login(auth0, true, { refresh_token: 'a_refresh_token' });

  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });

  //   mockFetch.mockResolvedValue(
  //     fetchResponse(true, {
  //       id_token: 'my_id_token',
  //       refresh_token: 'my_refresh_token',
  //       access_token: 'my_access_token',
  //       expires_in: 86400
  //     })
  //   );

  //   expect(utils.runIframe).not.toHaveBeenCalled();

  //   const access_token = await auth0.getTokenSilently({
  //     ignoreCache: true,
  //     custom_param: 'hello world'
  //   });

  //   expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
  //     redirect_uri: 'my_callback_url',
  //     client_id: 'auth0_client_id',
  //     grant_type: 'refresh_token',
  //     refresh_token: 'a_refresh_token',
  //     custom_param: 'hello world',
  //     another_custom_param: 'bar'
  //   });

  //   expect(access_token).toEqual('my_access_token');
  // });

  // it('checks the auth0 session when there is an auth cookie', async () => {
  //   const auth0 = await setup();

  //   jest.spyOn(<any>utils, 'runIframe').mockResolvedValue({
  //     access_token: 'my_access_token',
  //     state: 'MTIz'
  //   });

  //   (<jest.Mock>esCookie.get).mockReturnValue(true);
  //   // mockFetch.mockResolvedValueOnce(
  //   //   fetchResponse(true, {
  //   //     id_token: 'my_id_token',
  //   //     refresh_token: 'my_refresh_token',
  //   //     access_token: 'my_access_token',
  //   //     expires_in: 86400
  //   //   })
  //   // );
  //   await auth0.checkSession();

  //   expect(utils.runIframe).toHaveBeenCalled();
  // });
});
