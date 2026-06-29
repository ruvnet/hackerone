// Named error classes for API failures.
//
// Replaces generic `throw new Error("...")` so:
//   1. CLI can show the right hint (rate limit vs auth vs missing)
//   2. Callers can branch on instanceof (downstream tooling)
//   3. Error messages never echo the auth header or session cookie
//
// All error messages are constructed inside this module so we control
// what reaches stdout/stderr. Don't let an `unknown` payload (response
// body, header, etc.) be concatenated into a message at the throw site.

export class HackerOneApiError extends Error {
  readonly hint?: string;
  constructor(message: string, hint?: string) {
    super(message);
    this.name = 'HackerOneApiError';
    if (hint !== undefined) this.hint = hint;
  }
  toString(): string {
    return this.hint ? `${this.message}\n  hint: ${this.hint}` : this.message;
  }
}

/** 401 / auth-failed. Hint depends on transport. */
export class GraphQLAuthError extends HackerOneApiError {
  constructor(statusText: string) {
    super(
      `GraphQL endpoint refused auth (HTTP 401 ${statusText})`,
      'GraphQL needs X-Auth-Token (not Basic). For `me` / private programs ' +
        'also set HACKERONE_SESSION_COOKIE — token alone authenticates only public queries.',
    );
    this.name = 'GraphQLAuthError';
  }
}

/** GraphQL returned an `errors:[…]` block. */
export class GraphQLQueryError extends HackerOneApiError {
  readonly errors: ReadonlyArray<{ message: string }>;
  constructor(errors: ReadonlyArray<{ message: string }>) {
    super(
      'GraphQL query failed: ' + errors.map((e) => e.message).join('; '),
      'If the message mentions "undefinedField", the internal schema may ' +
        'have changed; pin to a known query in src/api/graphql-client.ts.',
    );
    this.name = 'GraphQLQueryError';
    this.errors = errors;
  }
}

export class RestAuthError extends HackerOneApiError {
  constructor(statusText: string) {
    super(
      `REST endpoint refused auth (HTTP 401 ${statusText})`,
      'HackerOne Basic auth uses <api-identifier>:<api-token>. Set ' +
        'HACKERONE_API_USERNAME to the API identifier shown at ' +
        'hackerone.com/users/<you>/api_tokens — NOT your profile username.',
    );
    this.name = 'RestAuthError';
  }
}

export class NotFoundError extends HackerOneApiError {
  constructor(what: string) {
    super(`${what} not found`);
    this.name = 'NotFoundError';
  }
}

export class RateLimitExceededError extends HackerOneApiError {
  constructor() {
    super(
      'Rate limit exceeded (token bucket empty — local-side cap)',
      'The HackerOne API has its own server-side limits too. Wait 60s ' +
        'or back off your batch size.',
    );
    this.name = 'RateLimitExceededError';
  }
}

export class TimeoutError extends HackerOneApiError {
  constructor(operation: string, ms: number) {
    super(`${operation} timed out after ${ms}ms`);
    this.name = 'TimeoutError';
  }
}
