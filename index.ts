// smart-launch.ts

class EventEmitter {
  private listeners: { [key in EventType]?: EventCallback[] } = {};

  /**
   * Subscribes to a specific event type.
   * @param event The event type to listen for.
   * @param callback The callback to execute when the event is emitted.
   */
  public on(event: EventType, callback: EventCallback): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event]?.push(callback);
  }

  /**
   * Unsubscribes a specific callback from an event type.
   * @param event The event type.
   * @param callback The callback to remove.
   */
  public off(event: EventType, callback: EventCallback): void {
    if (!this.listeners[event]) return;
    this.listeners[event] = this.listeners[event]?.filter(cb => cb !== callback);
  }

  /**
   * Emits an event to all subscribed listeners.
   * @param event The event object containing type and data.
   */
  public emit(event: Event): void {
    const callbacks = this.listeners[event.type];
    if (callbacks) {
      callbacks.forEach(callback => callback(event));
    }
  }
}

/**
 * Configuration required to initiate the SMART launch.
 */
export interface SmartLaunchConfig {
  clientId: string;
  redirectUri?: string; // Optional: Automatically detected if not provided
  scope: string;
  fhirBaseUrl: string; // Base URL of the FHIR server
  pkce?: 'always' | 'conditional' | 'never'; // PKCE configuration flag
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
}

/**
 * Represents the OAuth 2.0 token response with snake_case properties.
 */
export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  id_token?: string;
  patient?: string; // Directly extracted from the access token response
  encounter?: string; // Directly extracted from the access token response
}

/**
 * Represents the OAuth 2.0 discovery document.
 */
export interface OAuthDiscovery {
  issuer?: string;
  jwks_uri?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  [key: string]: any; // Additional fields as needed
}

type EventType =
  | 'launchInitiated'
  | 'authorizationSucceeded'
  | 'authorizationFailed'
  | 'tokenRefreshed'
  | 'tokenRefreshFailed';

interface Event {
  type: EventType;
  data?: any;
}

type EventCallback = (event: Event) => void;

/**
 * SmartLaunch class to manage OAuth 2.0 authorization flows with optional PKCE support.
 */
export class SmartLaunch {
  private config: SmartLaunchConfig;
  private codeVerifier: string | null = null;
  private smartConfig: OAuthDiscovery | null = null;
  private tokenResponse: AuthTokenResponse | null = null;
  private tokenExpiryTimeout: number | null = null;
  private authTab: Window | null = null;
  private state: string;
  private emitter: EventEmitter;
  private usePKCE: boolean = false; // Determines whether to use PKCE

  /**
   * A Promise that resolves with the AuthTokenResponse upon successful authorization,
   * or rejects with an error if the authorization fails.
   */
  public authPromise: Promise<AuthTokenResponse> | null = null;

  /**
   * An instance of EventEmitter to handle lifecycle events.
   */
  public events: EventEmitter;

  /**
   * References to the resolve and reject functions of the authPromise.
   * These are used to handle the promise externally in the handleMessage method.
   */
  private authPromiseResolve: ((value: AuthTokenResponse | PromiseLike<AuthTokenResponse>) => void) | null = null;
  private authPromiseReject: ((reason?: any) => void) | null = null;

  /**
   * Storage key prefix to ensure uniqueness based on configuration.
   */
  private storageKeyPrefix: string;

  /**
   * Private constructor to enforce the use of the static initialize method.
   * @param config The configuration for the SMART launch.
   */
  private constructor(config: SmartLaunchConfig) {
    this.config = config;
    this.state = this.generateState();
    this.emitter = new EventEmitter();
    this.events = this.emitter;

    // Create a unique storage key based on config to avoid conflicts
    this.storageKeyPrefix = `smartLaunch_${btoa(`${config.clientId}_${config.fhirBaseUrl}`)}`;

    // Listen for messages from the callback window
    window.addEventListener('message', this.handleMessage.bind(this));

    // Attempt to load token from session storage
    this.loadTokenFromSession();
  }

  /**
   * Static factory method to create an instance of SmartLaunch without initiating authorization.
   * @param config The configuration for the SMART launch.
   * @returns An instance of SmartLaunch.
   */
  public static initialize(config: SmartLaunchConfig): SmartLaunch {
    return new SmartLaunch(config);
  }

  /**
   * Initiates the authorization flow by performing discovery and opening the authorization window.
   * Must be called in response to a user action (e.g., button click) to comply with browser popup policies.
   * @returns A Promise that resolves with the AuthTokenResponse upon successful authorization.
   */
  public authorize(): Promise<AuthTokenResponse> {
    if (this.authPromise) {
      return this.authPromise;
    }

    this.authPromise = new Promise<AuthTokenResponse>((resolve, reject) => {
      this.authPromiseResolve = resolve;
      this.authPromiseReject = reject;
      this.initiateLaunch();
    });

    return this.authPromise;
  }

  /**
   * Initiates the authorization flow by performing discovery and opening the authorization window.
   */
  private async initiateLaunch(): Promise<void> {
    try {
      this.emitter.emit({ type: 'launchInitiated' });
      await this.performDiscovery();

      // Determine whether to use PKCE based on the config flag and discovery capabilities
      this.usePKCE = this.shouldUsePKCE();
      console.log("PKCE", this.usePKCE);

      if (this.usePKCE) {
        this.codeVerifier = this.generateCodeVerifier();
      }

      const codeChallenge = this.usePKCE ? await this.generateCodeChallenge(this.codeVerifier!) : undefined;
      const redirectUri = this.resolveRedirectUri();
      const url = this.buildAuthorizationUrl(codeChallenge, redirectUri, this.state);
      console.log(url);
      this.authTab = window.open(url, '_blank'); // Opens in a new tab

      if (!this.authTab) {
        throw new Error('Failed to open authorization window.');
      }
    } catch (error: any) {
      this.emitter.emit({ type: 'authorizationFailed', data: error });
      if (this.authPromiseReject) {
        this.authPromiseReject(error);
      }
    }
  }

  /**
   * Determines whether to use PKCE based on the configuration flag and discovery document.
   * @returns A boolean indicating whether PKCE should be used.
   */
  private shouldUsePKCE(): boolean {
    const pkceConfig = this.config.pkce || 'conditional';

    switch (pkceConfig) {
      case 'always':
        return true;
      case 'never':
        return false;
      case 'conditional':
      default:
        return (
          this.smartConfig?.code_challenge_methods_supported?.includes('S256') ??
          false
        );
    }
  }

  /**
   * Exchanges the authorization code for tokens.
   * @param code The authorization code received from the authorization server.
   * @param state The state parameter to associate the response with the correct launch.
   */
  private async exchangeCodeForToken(
    code: string,
    state: string
  ): Promise<void> {
    if (state !== this.state) {
      const error = new Error('Invalid state parameter.');
      this.emitter.emit({ type: 'authorizationFailed', data: error });
      if (this.authPromiseReject) {
        this.authPromiseReject(error);
      }
      return;
    }

    if (!this.smartConfig) {
      const error = new Error('SMART configuration not loaded.');
      this.emitter.emit({ type: 'authorizationFailed', data: error });
      if (this.authPromiseReject) {
        this.authPromiseReject(error);
      }
      return;
    }

    const bodyParams: { [key: string]: string } = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: this.resolveRedirectUri(),
      client_id: this.config.clientId,
    };

    if (this.usePKCE && this.codeVerifier) {
      bodyParams['code_verifier'] = this.codeVerifier;
    }

    const body = new URLSearchParams(bodyParams);

    try {
      const response = await fetch(this.smartConfig.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });

      if (!response.ok) {
        const errorResponse = await response.json();
        throw new Error(`Token exchange failed: ${JSON.stringify(errorResponse)}`);
      }

      const rawTokenResponse = await response.json();
      this.tokenResponse = rawTokenResponse as AuthTokenResponse;
      this.extractContext(this.tokenResponse);
      this.scheduleTokenRefresh(this.tokenResponse.expires_in);
      this.saveTokenToSession(this.tokenResponse); // Save to session storage
      this.emitter.emit({ type: 'authorizationSucceeded', data: this.tokenResponse });
      if (this.authPromiseResolve) {
        this.authPromiseResolve(this.tokenResponse);
      }

      // Close the authorization window after successful exchange
      if (this.authTab) {
        this.authTab.close();
      }
    } catch (error: any) {
      this.emitter.emit({ type: 'authorizationFailed', data: error });
      if (this.authPromiseReject) {
        this.authPromiseReject(error);
      }
    }
  }

  /**
   * Refreshes the access token using the refresh token.
   */
  public async refreshAccessToken(): Promise<AuthTokenResponse> {
    if (!this.smartConfig) {
      throw new Error('SMART configuration not loaded.');
    }
    if (!this.tokenResponse?.refresh_token) {
      throw new Error('No refresh token available.');
    }

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.tokenResponse.refresh_token,
      client_id: this.config.clientId,
    });

    try {
      const response = await fetch(this.smartConfig.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });

      if (!response.ok) {
        const errorResponse = await response.json();
        throw new Error(`Token refresh failed: ${JSON.stringify(errorResponse)}`);
      }

      const rawTokenResponse = await response.json();
      this.tokenResponse = rawTokenResponse as AuthTokenResponse;
      this.extractContext(this.tokenResponse);
      this.scheduleTokenRefresh(this.tokenResponse.expires_in);
      this.saveTokenToSession(this.tokenResponse); // Update session storage
      this.emitter.emit({ type: 'tokenRefreshed', data: this.tokenResponse });
      return this.tokenResponse;
    } catch (error: any) {
      this.emitter.emit({ type: 'tokenRefreshFailed', data: error });
      this.clearTokenFromSession(); // Clear tokens on failure
      throw error;
    }
  }

  /**
   * Makes an authenticated FHIR API call with string interpolation.
   * Supports placeholders like {{patient}} in the URL.
   * @param url The FHIR API endpoint relative to the FHIR base URL, with optional placeholders.
   * @param options Fetch options (e.g., method, headers, body).
   */
  public async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    if (!this.tokenResponse) {
      throw new Error('Not authenticated. Please initiate launch.');
    }

    // Perform string interpolation using patient and encounter from the token response
    const interpolatedUrl = this.interpolateUrl(url, this.tokenResponse.patient, this.tokenResponse.encounter);
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${this.tokenResponse.access_token}`);
    headers.set('Accept', `application/json`);

    let fullUrl;
    if (interpolatedUrl.startsWith('http://') || interpolatedUrl.startsWith('https://')) {
      // If the interpolated URL is absolute, use it as is
      fullUrl = interpolatedUrl;
    } else {
      // If the interpolated URL is relative, prepend the base URL
      const baseUrl = this.config.fhirBaseUrl.replace(/\/$/, '');
      const relativeUrl = interpolatedUrl.replace(/^\//, '');
      fullUrl = `${baseUrl}/${relativeUrl}`;
    }

    let response = await fetch(fullUrl, {
      headers,
      ...options,
    });

    if (response.status === 401) {
      // Attempt to refresh token if possible
      if (this.tokenResponse.refresh_token) {
        try {
          await this.refreshAccessToken();
          // Retry the original request with the new access token
          headers.set('Authorization', `Bearer ${this.tokenResponse.access_token}`);
          response = await fetch(fullUrl, {
            ...options,
            headers,
          });
        } catch (error) {
          throw new Error('Unauthorized and token refresh failed.');
        }
      } else {
        throw new Error('Unauthorized and no refresh token available.');
      }
    }

    return response;
  }

  /**
   * Builds the authorization URL based on the configuration and PKCE parameters.
   * @param codeChallenge The PKCE code challenge.
   * @param redirectUri The redirect URI.
   * @param state The state parameter.
   * @returns The complete authorization URL.
   */
  private buildAuthorizationUrl(codeChallenge: string | undefined, redirectUri: string, state: string): string {
    const params: { [key: string]: string } = {
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: this.config.scope,
      state: state,
      aud: this.config.fhirBaseUrl
    };

    if (this.usePKCE && codeChallenge) {
      params['code_challenge'] = codeChallenge;
      params['code_challenge_method'] = 'S256'; // Fixed to 'S256'
    }

    const queryString = new URLSearchParams(params).toString();
    return `${this.smartConfig?.authorization_endpoint}?${queryString}`;
  }

  /**
   * Extracts contextual information (patient and encounter) from the token response.
   * @param tokenResponse The AuthTokenResponse from the authorization server.
   */
  private extractContext(tokenResponse: AuthTokenResponse): void {
    // patient and encounter are already part of the tokenResponse
    // Additional context extraction can be done here if necessary
    // For example, extracting from id_token if needed
    // Currently, nothing extra is needed
  }

  /**
   * Performs discovery to fetch OAuth 2.0 endpoints and capabilities.
   */
  private async performDiscovery(): Promise<void> {
    const discoveryUrl = `${this.config.fhirBaseUrl.replace(/\/$/, '')}/.well-known/smart-configuration`;

    try {
      const response = await fetch(discoveryUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Discovery failed with status ${response.status}`);
      }

      this.smartConfig = await response.json();

      // Optionally override discovered endpoints with manual configuration
      if (this.config.authorizationEndpoint) {
        this.smartConfig.authorization_endpoint = this.config.authorizationEndpoint;
      }
      if (this.config.tokenEndpoint) {
        this.smartConfig.token_endpoint = this.config.tokenEndpoint;
      }

      // Validate required fields
      if (!this.smartConfig.authorization_endpoint || !this.smartConfig.token_endpoint) {
        throw new Error('Discovery document is missing required endpoints.');
      }

      // PKCE support is handled in shouldUsePKCE()
    } catch (error: any) {
      throw new Error(`Discovery error: ${error.message || error}`);
    }
  }

  /**
   * Resolves the redirect URI to an absolute URL.
   * If redirectUri is relative, resolves it against the current window's URL.
   * If redirectUri is omitted or empty, defaults to the current window's URL.
   */
  private resolveRedirectUri(): string {
    if (!this.config.redirectUri) {
      // Default to current window's URL (excluding hash)
      const ret = window.location.origin + window.location.pathname + window.location.search;

      return ret.replace(/\/$/, '');
    }

    // Check if redirectUri is absolute
    try {
      const url = new URL(this.config.redirectUri);
      return url.toString();
    } catch {
      // If not absolute, resolve relative to current window's URL
      return new URL(this.config.redirectUri, window.location.href).toString();
    }
  }

  /**
   * Handles messages received from the authorization tab.
   * @param event The MessageEvent received.
   */
  private async handleMessage(event: MessageEvent): Promise<void> {
    const expectedOrigin = new URL(this.resolveRedirectUri()).origin;

    // Verify the origin matches the redirect URI's origin
    if (event.origin !== expectedOrigin) {
      console.warn(`Ignored message from unexpected origin: ${event.origin}`);
      return;
    }

    const data = event.data;

    if (data.type === 'authorization_code') {
      const { code, state } = data;
      if (!code || !state) {
        const error = new Error('Authorization code or state is missing.');
        this.emitter.emit({ type: 'authorizationFailed', data: error });
        if (this.authPromiseReject) {
          this.authPromiseReject(error);
        }
        return;
      }

      try {
        await this.exchangeCodeForToken(code, state);
      } catch (error) {
        // Errors are already handled in exchangeCodeForToken
      }
    } else if (data.type === 'error') {
      const { error } = data;
      const err = new Error(`Authorization error: ${error}`);
      this.emitter.emit({ type: 'authorizationFailed', data: err });
      if (this.authPromiseReject) {
        this.authPromiseReject(err);
      }
    }
  }

  /**
   * Automatically handles the callback if this window is the redirect URI.
   * Detects authorization responses and processes them accordingly.
   */
  public static handleCallback(): void {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');

    if (code || error) {
      const message: any = {};
      if (code) {
        message.type = 'authorization_code';
        message.code = code;
        message.state = state;
      } else if (error) {
        message.type = 'error';
        message.error = error;
      }

      if (window.opener && window.opener !== window) {
        // Transmit the authorization response to the opener window
        window.opener.postMessage(message, window.location.origin);
        // Close the callback window after transmission
        window.close();
      }
    }
  }

  /**
   * Interpolates placeholders in the URL with values from the AuthTokenResponse.
   * Example: '/Patient/{{patient}}/Observation' -> '/Patient/12345/Observation'
   * @param url The URL with placeholders.
   * @param patientId The patient ID to replace the placeholder.
   * @param encounterId The encounter ID to replace the placeholder.
   * @returns The interpolated URL.
   */
  private interpolateUrl(url: string, patientId?: string, encounterId?: string): string {
    let interpolatedUrl = url;

    if (patientId) {
      interpolatedUrl = interpolatedUrl.replace(/{{\s*patient\s*}}/g, encodeURIComponent(patientId));
    }

    if (encounterId) {
      interpolatedUrl = interpolatedUrl.replace(/{{\s*encounter\s*}}/g, encodeURIComponent(encounterId));
    }

    return interpolatedUrl;
  }

  /**
   * Generates a random state parameter for CSRF protection.
   */
  private generateState(): string {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return Array.from(array, (dec) => dec.toString(16)).join('');
  }

  /**
   * Generates a code verifier for PKCE.
   */
  private generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return this.base64UrlEncode(array);
  }

  /**
   * Generates a code challenge from the code verifier.
   * @param codeVerifier The code verifier string.
   */
  private async generateCodeChallenge(codeVerifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const digest = await window.crypto.subtle.digest('SHA-256', data);
    return this.base64UrlEncode(new Uint8Array(digest));
  }

  /**
   * Encodes a Uint8Array to a Base64 URL-safe string.
   * @param array The Uint8Array to encode.
   */
  private base64UrlEncode(array: Uint8Array): string {
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /**
   * Schedules a token refresh before the current access token expires.
   * @param expiresIn The lifetime in seconds of the access token.
   */
  private scheduleTokenRefresh(expiresIn: number): void {
    if (this.tokenExpiryTimeout) {
      clearTimeout(this.tokenExpiryTimeout);
    }
    // Refresh 5 minutes before expiration
    const refreshTime = (expiresIn - 300) * 1000;
    if (refreshTime > 0 && this.tokenResponse?.refresh_token) {
      this.tokenExpiryTimeout = window.setTimeout(() => {
        this.refreshAccessToken().catch((error) => {
          console.error('Token refresh failed:', error);
        });
      }, refreshTime);
    }
  }

  /**
   * Saves the AuthTokenResponse to session storage.
   * @param tokenResponse The AuthTokenResponse to save.
   */
  private saveTokenToSession(tokenResponse: AuthTokenResponse): void {
    try {
      const tokenData = {
        tokenResponse,
        timestamp: Date.now(), // To track expiry
      };
      sessionStorage.setItem(this.storageKeyPrefix, JSON.stringify(tokenData));
    } catch (error) {
      console.error('Failed to save token to session storage:', error);
    }
  }

  /**
   * Loads the AuthTokenResponse from session storage if available and valid.
   */
  private async loadTokenFromSession(): void {
    try {
      const tokenDataString = sessionStorage.getItem(this.storageKeyPrefix);
      if (!tokenDataString) return;

      const tokenData = JSON.parse(tokenDataString) as { tokenResponse: AuthTokenResponse; timestamp: number };
      const { tokenResponse, timestamp } = tokenData;

      // Calculate elapsed time in seconds
      const elapsedSeconds = (Date.now() - timestamp) / 1000;

      if (elapsedSeconds < tokenResponse.expires_in) {
        // Token is still valid
        this.tokenResponse = tokenResponse;
        this.extractContext(this.tokenResponse);
        this.scheduleTokenRefresh(tokenResponse.expires_in - elapsedSeconds);
        setTimeout(() => {
            this.emitter.emit({ type: 'authorizationSucceeded', data: this.tokenResponse });
        });
      } else if (tokenResponse.refresh_token) {
        // Token expired but refresh token is available
        this.refreshAccessToken().catch(error => {
          console.error('Failed to refresh token on load:', error);
          this.clearTokenFromSession();
        });
      } else {
        // Token expired and no refresh token
        this.clearTokenFromSession();
      }
    } catch (error) {
      console.error('Failed to load token from session storage:', error);
      this.clearTokenFromSession();
    }
  }

  /**
   * Clears the AuthTokenResponse from session storage.
   */
  private clearTokenFromSession(): void {
    try {
      sessionStorage.removeItem(this.storageKeyPrefix);
      this.tokenResponse = null;
      if (this.tokenExpiryTimeout) {
        clearTimeout(this.tokenExpiryTimeout);
        this.tokenExpiryTimeout = null;
      }
    } catch (error) {
      console.error('Failed to clear token from session storage:', error);
    }
  }
}
