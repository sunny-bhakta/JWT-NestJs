import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'crypto';
import { durationStringToMs } from '../common/utils/duration.util';
import { SafeUser } from '../users/users.service';
import {
  RefreshTokenMetadata,
  RefreshTokenRecord,
} from './interfaces/refresh-token.interface';
import { TokenErrorException } from './errors/token-error.exception';
import { TokenEventsService } from './token-events.service';

const DEFAULT_REFRESH_TTL = '7d';

@Injectable()
export class RefreshTokensService {
  private readonly refreshTtlMs: number;
  private readonly tokens = new Map<string, RefreshTokenRecord>();

  constructor(
    private readonly configService: ConfigService,
    private readonly tokenEvents: TokenEventsService,
  ) {
    const ttlInput = this.configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
      DEFAULT_REFRESH_TTL,
    );
    this.refreshTtlMs = durationStringToMs(
      ttlInput ?? DEFAULT_REFRESH_TTL,
      7 * 24 * 60 * 60 * 1000,
    );
  }

  async issue(
    user: SafeUser,
    metadata?: RefreshTokenMetadata,
  ): Promise<{ token: string; expiresAt: Date }> {
    const token = randomBytes(48).toString('base64url');
    const record: RefreshTokenRecord = {
      tokenHash: this.hashToken(token),
      user,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.refreshTtlMs),
      metadata,
    };

    this.tokens.set(record.tokenHash, record);
    return { token, expiresAt: record.expiresAt };
  }

  async consume(refreshToken: string): Promise<SafeUser> {
    const record = this.findValidRecord(refreshToken);
    this.tokens.delete(record.tokenHash);
    return record.user;
  }

  async revoke(refreshToken: string): Promise<void> {
    const record = this.findValidRecord(refreshToken);
    this.tokens.delete(record.tokenHash);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    let removed = 0;
    for (const [key, value] of this.tokens.entries()) {
      if (value.user.id === userId) {
        this.tokens.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  get refreshTtl(): number {
    return this.refreshTtlMs;
  }

  private findValidRecord(refreshToken: string): RefreshTokenRecord {
    const hash = this.hashToken(refreshToken);
    const record = this.tokens.get(hash);
    if (!record) {
      this.tokenEvents.logRefreshTokenFailure({
        code: 'REFRESH_TOKEN_INVALID',
        reason: 'Refresh token not found or already used',
        refreshTokenHash: hash,
      });
      throw new TokenErrorException('REFRESH_TOKEN_INVALID');
    }

    if (record.expiresAt.getTime() < Date.now()) {
      this.tokens.delete(hash);
      this.tokenEvents.logRefreshTokenFailure({
        code: 'REFRESH_TOKEN_EXPIRED',
        reason: 'Refresh token expired',
        refreshTokenHash: hash,
      });
      throw new TokenErrorException('REFRESH_TOKEN_EXPIRED');
    }

    return { ...record, tokenHash: hash };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

}
