import { UnauthorizedException } from '@nestjs/common';

export type TokenErrorCode =
  | 'ACCESS_TOKEN_MISSING'
  | 'ACCESS_TOKEN_EXPIRED'
  | 'ACCESS_TOKEN_INVALID'
  | 'REFRESH_TOKEN_INVALID'
  | 'REFRESH_TOKEN_EXPIRED';

const DEFAULT_MESSAGES: Record<TokenErrorCode, string> = {
  ACCESS_TOKEN_MISSING: 'Provide an access token in the Authorization header.',
  ACCESS_TOKEN_EXPIRED: 'Your access token has expired. Please refresh and try again.',
  ACCESS_TOKEN_INVALID: 'Access token is invalid or has been tampered with.',
  REFRESH_TOKEN_INVALID: 'Refresh token is invalid or has already been used.',
  REFRESH_TOKEN_EXPIRED: 'Refresh token has expired. Log in again to obtain a new session.',
};

export class TokenErrorException extends UnauthorizedException {
  constructor(public readonly code: TokenErrorCode, message?: string) {
    super({
      statusCode: 401,
      error: 'Unauthorized',
      code,
      message: message ?? DEFAULT_MESSAGES[code],
    });
  }
}
