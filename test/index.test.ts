import 'fast-text-encoding';
var kill = require('tree-kill');
import { verify } from '../src/jwt';
import { IdToken } from '../src';
import * as utils from '../src/utils';
import {
  expectToHaveBeenCalledWithAuth0ClientParam,
  BASE_URL,
  startST
} from './helpers';
import createAuth0Client, {
  Auth0Client,
  GetTokenSilentlyOptions
} from '../src/index';
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

let fetch = (global as any).fetch;

jest.mock('browser-tabs-lock');
jest.mock('../src/jwt');
jest.mock('../src/storage');
jest.mock('../src/transaction-manager');
jest.mock('../src/utils');

import { CacheLocation, Auth0ClientOptions } from '../src/global';
import * as scope from '../src/scope';

import { AuthenticationError } from '../src/errors';
import version from '../src/version';

import { DEFAULT_POPUP_CONFIG_OPTIONS, DEFAULT_SCOPE } from '../src/constants';

const GET_TOKEN_SILENTLY_LOCK_KEY = 'auth0.lock.getTokenSilently';

const TEST_DOMAIN = 'auth0_domain';
const TEST_CLIENT_ID = 'auth0_client_id';
const TEST_QUERY_PARAMS = 'query=params';
const TEST_SCOPES = DEFAULT_SCOPE;
const TEST_ENCODED_STATE = 'encoded-state';
const TEST_RANDOM_STRING = 'random-string';
const TEST_ARRAY_BUFFER = 'this-is-an-array-buffer';
const TEST_BASE64_ENCODED_STRING = 'base64-url-encoded-string';
const TEST_CODE = 'code';
const TEST_ID_TOKEN = 'id-token';
const TEST_ACCESS_TOKEN = 'access-token';
const TEST_REFRESH_TOKEN = 'refresh-token';
const TEST_USER_ID = 'user-id';
const TEST_USER_EMAIL = 'user@email.com';
const TEST_APP_STATE = { bestPet: 'dog' };
const TEST_AUTH0_CLIENT_QUERY_STRING = `&auth0Client=${encodeURIComponent(
  btoa(
    JSON.stringify({
      name: 'auth0-spa-js',
      version: version
    })
  )
)}`;

const mockEnclosedCache = {
  get: jest.fn(),
  save: jest.fn(),
  clear: jest.fn()
};

jest.mock('../src/cache', () => ({
  InMemoryCache: () => ({
    enclosedCache: mockEnclosedCache
  }),
  LocalStorageCache: () => mockEnclosedCache
}));

jest.mock('../src/token.worker');

const webWorkerMatcher = expect.objectContaining({
  postMessage: expect.any(Function)
});

// const setup = async (
//     config?: Partial<Auth0ClientOptions>,
//     claims?: Partial<IdToken>
// ) => {
//     const auth0 = new Auth0Client(
//         Object.assign(
//             {
//                 domain: 'auth0_domain',
//                 client_id: 'auth0_client_id',
//                 redirect_uri: 'my_callback_url'
//             },
//             config
//         )
//     );

//     mockVerify.mockReturnValue({
//         claims: Object.assign(
//             {
//                 exp: Date.now() / 1000 + 86400
//             },
//             claims
//         )
//     });

//     return auth0;
// };

const setup = async (clientOptions: Partial<Auth0ClientOptions> = {}) => {
  const auth0 = await createAuth0Client({
    domain: TEST_DOMAIN,
    client_id: TEST_CLIENT_ID,
    ...clientOptions
  });

  // const getDefaultInstance = m => require(m).default.mock.instances[0];

  const storage = {
    get: require('../src/storage').get,
    save: require('../src/storage').save,
    remove: require('../src/storage').remove
  };

  const lock = require('browser-tabs-lock');
  const cache = mockEnclosedCache;

  const tokenVerifier = require('../src/jwt').verify;
  // const transactionManager = getDefaultInstance('../src/transaction-manager');
  const utils = require('../src/utils');

  utils.createQueryParams.mockReturnValue(TEST_QUERY_PARAMS);
  utils.encode.mockReturnValue(TEST_ENCODED_STATE);
  utils.createRandomString.mockReturnValue(TEST_RANDOM_STRING);
  utils.sha256.mockReturnValue(Promise.resolve(TEST_ARRAY_BUFFER));
  utils.bufferToBase64UrlEncoded.mockReturnValue(TEST_BASE64_ENCODED_STRING);

  utils.parseQueryResult.mockReturnValue({
    state: TEST_ENCODED_STATE,
    code: TEST_CODE
  });

  utils.runPopup.mockReturnValue(
    Promise.resolve({ state: TEST_ENCODED_STATE, code: TEST_CODE })
  );

  utils.runIframe.mockReturnValue(
    Promise.resolve({ state: TEST_ENCODED_STATE, code: TEST_CODE })
  );

  utils.oauthToken.mockReturnValue(
    Promise.resolve({
      id_token: TEST_ID_TOKEN,
      access_token: TEST_ACCESS_TOKEN
    })
  );

  // tokenVerifier.mockReturnValue({
  //     user: {
  //         sub: TEST_USER_ID
  //     },
  //     claims: {
  //         sub: TEST_USER_ID,
  //         aud: TEST_CLIENT_ID
  //     }
  // });

  // const popup = {
  //     location: { href: '' },
  //     close: jest.fn()
  // };

  return {
    auth0,
    storage,
    cache,
    tokenVerifier,
    // transactionManager,
    utils,
    lock
    // popup
  };
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

let child;

describe('index', () => {
  beforeAll(async () => {
    child = spawn('./test/startServer', [
      process.env.INSTALL_PATH,
      process.env.NODE_PORT === undefined ? 8080 : process.env.NODE_PORT
    ]);
    await new Promise(r => setTimeout(r, 1000));
  });

  afterAll(async function () {
    let instance = axios.create();
    await instance.post(BASE_URL + '/after');
    try {
      kill(child.pid);
    } catch (err) {}
  });

  beforeEach(async () => {
    try {
      await fetch(BASE_URL + '/logout', { method: 'POST' });
    } catch (ignored) {}
    mockWindow.location.assign = jest.fn();
    mockWindow.crypto = {
      subtle: {
        digest: () => 'foo'
      },
      getRandomValues() {
        return '123';
      }
    };
    mockWindow.Worker = {};
    jest.spyOn(scope, 'getUniqueScopes');
    let instance = axios.create();
    await instance.post(BASE_URL + '/beforeeach');
    await new Promise(r => setTimeout(r, 1000));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should create an Auth0 client', async () => {
    const auth0 = await createAuth0Client({
      domain: TEST_DOMAIN,
      client_id: TEST_CLIENT_ID
    });

    expect(auth0).toBeInstanceOf(Auth0Client);
  });

  it('should call `utils.validateCrypto`', async () => {
    const { utils } = await setup();

    expect(utils.validateCrypto).toHaveBeenCalled();
  });

  it('should fail if an invalid cache location was given', async () => {
    await expect(
      createAuth0Client({
        domain: TEST_DOMAIN,
        client_id: TEST_CLIENT_ID,
        cacheLocation: 'dummy'
      } as any)
    ).rejects.toThrow(new Error('Invalid cache location "dummy"'));
  });

  // it('should absorb \'login_required\'', async () => {
  //     await startST()
  //     const { utils, storage } = await setup();

  //     utils.runIframe.mockImplementation(() => {
  //         throw {
  //             error: 'login_required',
  //             error_message: 'Login required'
  //         };
  //     });

  //     storage.get.mockReturnValue(true);

  //     const auth0 = await createAuth0Client({
  //         domain: TEST_DOMAIN,
  //         client_id: TEST_CLIENT_ID
  //     });

  //     // expect(auth0).toBeInstanceOf(Auth0Client);
  //     // expect(utils.runIframe).toHaveBeenCalled();
  // });

  // it('should absorb other recoverable errors', async () => {
  //     const { utils, storage } = await setup();
  //     storage.get.mockReturnValue(true);
  //     const recoverableErrors = [
  //         'consent_required',
  //         'interaction_required',
  //         'account_selection_required',
  //         'access_denied'
  //     ];

  //     for (let error of recoverableErrors) {
  //         utils.runIframe.mockRejectedValue({ error });
  //         const auth0 = await createAuth0Client({
  //             domain: TEST_DOMAIN,
  //             client_id: TEST_CLIENT_ID
  //         });
  //         expect(auth0).toBeInstanceOf(Auth0Client);
  //         expect(utils.runIframe).toHaveBeenCalledTimes(1);
  //         utils.runIframe.mockClear();
  //     }
  // });
});
