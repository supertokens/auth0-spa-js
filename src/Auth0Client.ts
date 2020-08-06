import Lock from 'browser-tabs-lock';

import {
  createQueryParams,
  runPopup,
  parseQueryResult,
  encode,
  createRandomString,
  runIframe,
  sha256,
  bufferToBase64UrlEncoded,
  oauthToken,
  validateCrypto
} from './utils';
let SuperTokensFetch = require('supertokens-website').default;

import { getUniqueScopes } from './scope';
import { InMemoryCache, ICache, LocalStorageCache } from './cache';
import TransactionManager from './transaction-manager';
import { verify as verifyIdToken } from './jwt';
import { AuthenticationError } from './errors';
import * as ClientStorage from './storage';

import {
  CACHE_LOCATION_MEMORY,
  DEFAULT_POPUP_CONFIG_OPTIONS,
  DEFAULT_AUTHORIZE_TIMEOUT_IN_SECONDS,
  MISSING_REFRESH_TOKEN_ERROR_MESSAGE,
  DEFAULT_SCOPE,
  RECOVERABLE_ERRORS
} from './constants';

import version from './version';

import {
  Auth0ClientOptions,
  BaseLoginOptions,
  AuthorizeOptions,
  RedirectLoginOptions,
  PopupLoginOptions,
  PopupConfigOptions,
  GetUserOptions,
  GetIdTokenClaimsOptions,
  RedirectLoginResult,
  GetTokenSilentlyOptions,
  GetTokenWithPopupOptions,
  LogoutOptions,
  RefreshTokenOptions,
  OAuthTokenOptions,
  CacheLocation
} from './global';

// @ts-ignore
import TokenWorker from './token.worker.ts';

/**
 * @ignore
 */
const lock = new Lock();

/**
 * @ignore
 */
const GET_TOKEN_SILENTLY_LOCK_KEY = 'auth0.lock.getTokenSilently';

/**
 * @ignore
 */
const cacheLocationBuilders = {
  memory: () => new InMemoryCache().enclosedCache,
  localstorage: () => new LocalStorageCache()
};

/**
 * @ignore
 */
const cacheFactory = (location: string) => {
  return cacheLocationBuilders[location];
};

/**
 * @ignore
 */
const isIE11 = () => /Trident.*rv:11\.0/.test(navigator.userAgent);

/**
 * @ignore
 */
const getTokenIssuer = (issuer, domainUrl) => {
  if (issuer) {
    return issuer.startsWith('https://') ? issuer : `https://${issuer}/`;
  }
  return `${domainUrl}/`;
};

/**
 * @ignore
 */
const getCustomInitialOptions = (
  options: Auth0ClientOptions
): BaseLoginOptions => {
  const {
    advancedOptions,
    audience,
    auth0Client,
    authorizeTimeoutInSeconds,
    cacheLocation,
    client_id,
    domain,
    issuer,
    leeway,
    max_age,
    redirect_uri,
    scope,
    useRefreshTokens,
    ...customParams
  } = options;
  return customParams;
};

export default class Auth0Client {
  private cache: ICache;
  private transactionManager: TransactionManager;
  private customOptions: BaseLoginOptions;
  private domainUrl: string;
  private tokenIssuer: string;
  private defaultScope: string;
  private scope: string;

  cacheLocation: CacheLocation;
  private worker: Worker;

  constructor(private options: Auth0ClientOptions) {
    typeof window !== 'undefined' && validateCrypto();
    this.cacheLocation = options.cacheLocation || CACHE_LOCATION_MEMORY;

    if (!cacheFactory(this.cacheLocation)) {
      throw new Error(`Invalid cache location "${this.cacheLocation}"`);
    }

    this.cache = cacheFactory(this.cacheLocation)();
    this.scope = this.options.scope;
    this.transactionManager = new TransactionManager();
    this.domainUrl = `https://${this.options.domain}`;
    this.tokenIssuer = getTokenIssuer(this.options.issuer, this.domainUrl);

    this.defaultScope = getUniqueScopes(
      'openid',
      this.options?.advancedOptions?.defaultScope !== undefined
        ? this.options.advancedOptions.defaultScope
        : DEFAULT_SCOPE
    );

    if (this.options.useRefreshTokens) {
      this.scope = getUniqueScopes(this.scope, 'offline_access');
    }

    this.customOptions = getCustomInitialOptions(options);
  }

  private _url(path) {
    const auth0Client = encodeURIComponent(
      btoa(
        JSON.stringify(
          this.options.auth0Client || {
            name: 'auth0-spa-js',
            version: version
          }
        )
      )
    );
    return `${this.domainUrl}${path}&auth0Client=${auth0Client}`;
  }

  private _getParams(
    authorizeOptions: BaseLoginOptions,
    state: string,
    nonce: string,
    redirect_uri: string
  ): AuthorizeOptions {
    const {
      domain,
      leeway,
      useRefreshTokens,
      auth0Client,
      cacheLocation,
      advancedOptions,
      ...withoutDomain
    } = this.options;

    return {
      ...withoutDomain,
      ...authorizeOptions,
      scope: getUniqueScopes(
        this.defaultScope,
        this.scope,
        authorizeOptions.scope
      ),
      response_type: 'code',
      response_mode: 'query',
      state,
      nonce,
      redirect_uri: redirect_uri || this.options.redirect_uri
    };
  }
  private _authorizeUrl(authorizeOptions: AuthorizeOptions) {
    return this._url(`/authorize?${createQueryParams(authorizeOptions)}`);
  }
  private _verifyIdToken(id_token: string, nonce?: string) {
    return verifyIdToken({
      iss: this.tokenIssuer,
      aud: this.options.client_id,
      id_token,
      nonce,
      leeway: this.options.leeway,
      max_age: this._parseNumber(this.options.max_age)
    });
  }
  private _parseNumber(value: any): number {
    if (typeof value !== 'string') {
      return value;
    }
    return parseInt(value, 10) || undefined;
  }

  /**
   * ```js
   * await auth0.buildAuthorizeUrl(options);
   * ```
   *
   * Builds an `/authorize` URL for loginWithRedirect using the parameters
   * provided as arguments. Random and secure `state` and `nonce`
   * parameters will be auto-generated.
   *
   * @param options
   */

  public async buildAuthorizeUrl(
    options: RedirectLoginOptions = {}
  ): Promise<string> {
    const { redirect_uri, appState, ...authorizeOptions } = options;

    const stateIn = encode(createRandomString());
    const nonceIn = encode(createRandomString());
    const fragment = options.fragment ? `#${options.fragment}` : '';

    const params = this._getParams(
      authorizeOptions,
      stateIn,
      nonceIn,
      redirect_uri
    );

    const url = this._authorizeUrl(params);

    this.transactionManager.create(stateIn, {
      nonce: nonceIn,
      appState,
      scope: params.scope,
      audience: params.audience || 'default',
      redirect_uri: params.redirect_uri
    });

    return url + fragment;
  }

  /**
   * ```js
   * await auth0.loginWithPopup(options);
   * ```
   *
   * Opens a popup with the `/authorize` URL using the parameters
   * provided as arguments. Random and secure `state` and `nonce`
   * parameters will be auto-generated. If the response is successful,
   * results will be valid according to their expiration times.
   *
   * IMPORTANT: This method has to be called from an event handler
   * that was started by the user like a button click, for example,
   * otherwise the popup will be blocked in most browsers.
   *
   * @param options
   */
  public async loginWithPopup(
    options: PopupLoginOptions = {},
    config: PopupConfigOptions = {}
  ) {
    // TODO:
    throw new Error('Not supported yet');
  }

  /**
   * ```js
   * const user = await auth0.getUser();
   * ```
   *
   * Returns the user information if available (decoded
   * from the `id_token`).
   *
   * @param options
   */
  public async getUser(
    options: GetUserOptions = {
      audience: this.options.audience || 'default',
      scope: this.scope || this.defaultScope
    }
  ) {
    if (!(await this.isAuthenticated())) {
      return undefined;
    }
    options.scope = getUniqueScopes(this.defaultScope, options.scope);

    const cache = this.cache.get({
      client_id: this.options.client_id,
      ...options
    });

    return cache && cache.decodedToken && cache.decodedToken.user;
  }

  /**
   * ```js
   * const claims = await auth0.getIdTokenClaims();
   * ```
   *
   * Returns all claims from the id_token if available.
   *
   * @param options
   */
  public async getIdTokenClaims(
    options: GetIdTokenClaimsOptions = {
      audience: this.options.audience || 'default',
      scope: this.scope || this.defaultScope
    }
  ) {
    if (!(await this.isAuthenticated())) {
      return undefined;
    }
    options.scope = getUniqueScopes(
      this.defaultScope,
      this.scope,
      options.scope
    );

    const cache = this.cache.get({
      client_id: this.options.client_id,
      ...options
    });

    return cache && cache.decodedToken && cache.decodedToken.claims;
  }

  /**
   * ```js
   * await auth0.loginWithRedirect(options);
   * ```
   *
   * Performs a redirect to `/authorize` using the parameters
   * provided as arguments. Random and secure `state` and `nonce`
   * parameters will be auto-generated.
   *
   * @param options
   */
  public async loginWithRedirect(options: RedirectLoginOptions = {}) {
    const url = await this.buildAuthorizeUrl(options);
    window.location.assign(url);
  }

  /**
   * After the browser redirects back to the callback page,
   * call `handleRedirectCallback` to handle success and error
   * responses from Auth0. If the response is successful, results
   * will be valid according to their expiration times.
   */
  public async handleRedirectCallback(
    url: string = window.location.href
  ): Promise<RedirectLoginResult> {
    const queryStringFragments = url.split('?').slice(1);
    if (queryStringFragments.length === 0) {
      throw new Error('There are no query params available for parsing.');
    }
    const { state, code, error, error_description } = parseQueryResult(
      queryStringFragments.join('')
    );

    const transaction = this.transactionManager.get(state);

    if (!transaction) {
      throw new Error('Invalid state');
    }

    if (error) {
      this.transactionManager.remove(state);

      throw new AuthenticationError(
        error,
        error_description,
        state,
        transaction.appState
      );
    }

    this.transactionManager.remove(state);
    let response = await this._callAPI({
      action: 'login',
      code,
      redirect_uri: transaction.redirect_uri
    });

    let id_token = response.id_token;

    let expires_in = response.expires_in;

    const decodedToken = this._verifyIdToken(id_token, transaction.nonce);

    const cacheEntry = {
      id_token,
      expires_in,
      decodedToken,
      audience: transaction.audience,
      scope: transaction.scope,
      client_id: this.options.client_id
    };

    this.cache.save(cacheEntry);

    ClientStorage.save('auth0.is.authenticated', true, { daysUntilExpire: 1 });

    return {
      appState: transaction.appState
    };
  }

  public async checkSession(options?: GetTokenSilentlyOptions) {
    if (!(await this.isAuthenticated())) {
      return;
    }

    try {
      await this.getTokenSilently(options);
    } catch (error) {
      if (!RECOVERABLE_ERRORS.includes(error.error)) {
        throw error;
      }
    }
  }

  public async getTokenSilently(
    options: GetTokenSilentlyOptions = {}
  ): Promise<any> {
    const { ignoreCache, ...getTokenOptions } = {
      audience: this.options.audience,
      ignoreCache: false,
      ...options,
      scope: getUniqueScopes(this.defaultScope, this.scope, options.scope)
    };

    try {
      await lock.acquireLock(GET_TOKEN_SILENTLY_LOCK_KEY, 5000);

      if (!ignoreCache) {
        const cache = this.cache.get(
          {
            scope: getTokenOptions.scope,
            audience: getTokenOptions.audience || 'default',
            client_id: this.options.client_id
          },
          60 // get a new token if within 60 seconds of expiring
        );

        if (cache && cache.id_token) {
          await lock.releaseLock(GET_TOKEN_SILENTLY_LOCK_KEY);
          return;
        }
      }

      const authResult = this.options.useRefreshTokens
        ? await this._getTokenUsingRefreshToken(getTokenOptions)
        : await this._getTokenFromIFrame(getTokenOptions);

      this.cache.save({ client_id: this.options.client_id, ...authResult });

      ClientStorage.save('auth0.is.authenticated', true, {
        daysUntilExpire: 1
      });

      return;
    } catch (e) {
      if (e.message === 'Login required' || e.message === 'Consent required') {
        // if e.message === "Consent required", then we mimic the behaviour of Auth0's actual lib
        try {
          await this._logout({
            localOnly:
              (await this.isAuthenticated()) || e.message === 'Consent required'
          });
        } catch (err) {
          if (await this.isAuthenticated()) {
            // something went wrong while destroying SuperTokens' session
            throw err;
          }
        }
      }
      throw e;
    } finally {
      await lock.releaseLock(GET_TOKEN_SILENTLY_LOCK_KEY);
    }
  }

  async _callAPI(body) {
    let path: string | undefined = SuperTokensFetch.getAuth0API().apiPath;
    if (path === undefined) {
      path = '/supertokens-auth0';
    }
    let responseRaw = await SuperTokensFetch.fetch(
      SuperTokensFetch.getRefreshURLDomain() + path,
      {
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify(body),
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );

    if (responseRaw.status >= 400) {
      throw responseRaw;
    }

    return await responseRaw.json();
  }

  /**
   * ```js
   * const token = await auth0.getTokenWithPopup(options);
   * ```
   * Opens a popup with the `/authorize` URL using the parameters
   * provided as arguments. Random and secure `state` and `nonce`
   * parameters will be auto-generated. If the response is successful,
   * results will be valid according to their expiration times.
   *
   * @param options
   */
  public async getTokenWithPopup(
    options: GetTokenWithPopupOptions = {
      audience: this.options.audience,
      scope: this.scope || this.defaultScope
    },
    config: PopupConfigOptions = DEFAULT_POPUP_CONFIG_OPTIONS
  ): Promise<string> {
    throw new Error('Not allowed');
  }

  /**
   * ```js
   * const isAuthenticated = await auth0.isAuthenticated();
   * ```
   *
   * Returns `true` if there's valid information stored,
   * otherwise returns `false`.
   *
   */
  public async isAuthenticated() {
    return SuperTokensFetch.doesSessionExist();
  }

  /**
   * ```js
   * auth0.logout();
   * ```
   *
   * Clears the application session and performs a redirect to `/v2/logout`, using
   * the parameters provided as arguments, to clear the Auth0 session.
   * If the `federated` option is specified it also clears the Identity Provider session.
   * If the `localOnly` option is specified, it only clears the application session.
   * It is invalid to set both the `federated` and `localOnly` options to `true`,
   * and an error will be thrown if you do.
   * [Read more about how Logout works at Auth0](https://auth0.com/docs/logout).
   *
   * @param options
   */
  public logout = (options: LogoutOptions = {}) => {
    this._logout(options);
  };

  private _logout = async (options: LogoutOptions = {}) => {
    if (await this.isAuthenticated()) {
      try {
        await this._callAPI({
          action: 'logout'
        });
      } catch (err) {
        if (await this.isAuthenticated()) {
          throw err;
        }
      }
    }

    if (options.client_id !== null) {
      options.client_id = options.client_id || this.options.client_id;
    } else {
      delete options.client_id;
    }

    const { federated, localOnly, ...logoutOptions } = options;

    if (localOnly && federated) {
      throw new Error(
        'It is invalid to set both the `federated` and `localOnly` options to `true`'
      );
    }

    this.cache.clear();
    ClientStorage.remove('auth0.is.authenticated');

    if (localOnly) {
      return;
    }

    const federatedQuery = federated ? `&federated` : '';
    const url = this._url(`/v2/logout?${createQueryParams(logoutOptions)}`);

    window.location.assign(`${url}${federatedQuery}`);
  };

  private async _getTokenFromIFrame(
    options: GetTokenSilentlyOptions
  ): Promise<any> {
    const stateIn = encode(createRandomString());
    const nonceIn = encode(createRandomString());

    const params = this._getParams(
      options,
      stateIn,
      nonceIn,
      options.redirect_uri ||
        this.options.redirect_uri ||
        window.location.origin
    );

    const url = this._authorizeUrl({
      ...params,
      prompt: 'none',
      response_mode: 'web_message'
    });

    const timeout =
      options.timeoutInSeconds || this.options.authorizeTimeoutInSeconds;
    const codeResult = await runIframe(url, this.domainUrl, timeout);

    if (stateIn !== codeResult.state) {
      throw new Error('Invalid state');
    }
    let response;
    try {
      response = await this._callAPI({
        action: 'refresh',
        code: codeResult.code,
        redirect_uri: params.redirect_uri
      });
    } catch (err) {
      if (!(await this.isAuthenticated())) {
        throw new Error('Login required');
      }
      throw err;
    }

    let id_token = response.id_token;

    let expires_in = response.expires_in;

    const decodedToken = this._verifyIdToken(id_token, nonceIn);

    return {
      id_token,
      expires_in,
      decodedToken,
      scope: params.scope,
      audience: params.audience || 'default'
    };
  }

  private async _getTokenUsingRefreshToken(
    options: GetTokenSilentlyOptions
  ): Promise<any> {
    options.scope = getUniqueScopes(
      this.defaultScope,
      this.options.scope,
      options.scope
    );

    let response;

    try {
      response = await this._callAPI({
        action: 'refresh'
      });
    } catch (e) {
      if (!(await this.isAuthenticated())) {
        throw new Error('Login required');
      }
      if (e.status >= 400 && e.status < 500 && (await this.isAuthenticated())) {
        return await this._getTokenFromIFrame(options);
      }
      throw e;
    }

    let id_token = response.id_token;

    let expires_in = response.expires_in;

    const decodedToken = this._verifyIdToken(response.id_token);

    return {
      id_token,
      expires_in,
      decodedToken,
      scope: options.scope,
      audience: options.audience || 'default'
    };
  }
}
