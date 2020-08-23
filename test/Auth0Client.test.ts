import 'fast-text-encoding';
import Auth0Client from '../src/Auth0Client';
import { verify } from '../src/jwt';
import { MessageChannel } from 'worker_threads';
import { Auth0ClientOptions, IdToken } from '../src';
import * as scope from '../src/scope';
import {
  expectToHaveBeenCalledWithAuth0ClientParam,
  BASE_URL,
  startST
} from './helpers';
import SuperTokensRequest from 'supertokens-website';
const nodeFetch = require('node-fetch');
const fetch = require('fetch-cookie')(nodeFetch);
const { spawn } = require('child_process');
let axios = require('axios');

jest.mock('unfetch');
jest.mock('es-cookie');
jest.mock('../src/jwt');
jest.mock('../src/token.worker');

jest.unmock('browser-tabs-lock');

const mockWindow = <any>global;
mockWindow.fetch = fetch;
const mockVerify = <jest.Mock>verify;

const setup = (
  config?: Partial<Auth0ClientOptions>,
  claims?: Partial<IdToken>
) => {
  SuperTokensRequest.init({
    refreshTokenUrl: 'http://localhost:8080/refresh',
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
    try {
      await instance.get(BASE_URL + '/stop');
    } catch (err) {}
  });

  beforeEach(async () => {
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
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should log the user in with custom auth0Client', async () => {
    await startST();
    const auth0Client = { name: '__test_client__', version: '0.0.0' };
    const auth0 = setup({ auth0Client });
    await login(auth0);
    expectToHaveBeenCalledWithAuth0ClientParam(
      mockWindow.location.assign,
      auth0Client
    );
    expect(await auth0.isAuthenticated()).toBeTruthy();
  });

  it('ensures the openid scope is defined when customizing default scopes', () => {
    const auth0 = setup({
      advancedOptions: {
        defaultScope: 'test-scope'
      }
    });
    expect((<any>auth0).defaultScope).toBe('openid test-scope');
  });

  it('allows an empty custom default scope', () => {
    const auth0 = setup({
      advancedOptions: {
        defaultScope: null
      }
    });

    expect((<any>auth0).defaultScope).toBe('openid');
  });

  it('should create issuer from domain', () => {
    const auth0 = setup({
      domain: 'test.dev'
    });

    expect((<any>auth0).tokenIssuer).toEqual('https://test.dev/');
  });

  it('should allow issuer as a domain', () => {
    const auth0 = setup({
      issuer: 'foo.bar.com'
    });

    expect((<any>auth0).tokenIssuer).toEqual('https://foo.bar.com/');
  });

  it('should allow issuer as a fully qualified url', () => {
    const auth0 = setup({
      issuer: 'https://some.issuer.com/'
    });

    expect((<any>auth0).tokenIssuer).toEqual('https://some.issuer.com/');
  });
});
