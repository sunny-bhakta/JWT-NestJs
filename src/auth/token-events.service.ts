import { Injectable, Logger } from '@nestjs/common';
import { Request } from 'express';

export interface TokenFailureContext {
  code: string;
  reason: string;
  request?: Request;
}

@Injectable()
export class TokenEventsService {
  private readonly logger = new Logger(TokenEventsService.name);

  logAccessTokenFailure(context: TokenFailureContext) {
    this.logger.warn({
      event: 'access_token_failure',
      code: context.code,
      reason: context.reason,
      ip: context.request?.ip,
      userAgent: context.request?.headers['user-agent'],
      path: context.request?.path,
    });
  }

  logRefreshTokenFailure(context: TokenFailureContext & { refreshTokenHash?: string }) {
    this.logger.warn({
      event: 'refresh_token_failure',
      code: context.code,
      reason: context.reason,
      ip: context.request?.ip,
      userAgent: context.request?.headers['user-agent'],
      path: context.request?.path,
      refreshTokenHash: context.refreshTokenHash,
    });
  }
}
