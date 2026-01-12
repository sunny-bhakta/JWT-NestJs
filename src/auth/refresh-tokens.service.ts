import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { durationStringToMs } from '../common/utils/duration.util';
import { SafeUser } from '../users/users.service';
import {
  RefreshSessionSnapshot,
  RefreshTokenMetadata,
} from './interfaces/refresh-token.interface';
import { TokenErrorException } from './errors/token-error.exception';
import { TokenEventsService } from './token-events.service';
import { RefreshSessionEntity } from './entities/refresh-session.entity';

const DEFAULT_REFRESH_TTL = '7d';
const DEFAULT_REFRESH_MAX_LIFETIME = '30d';

@Injectable()
export class RefreshTokensService {
  private readonly refreshTtlMs: number;
  private readonly refreshMaxLifetimeMs: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly tokenEvents: TokenEventsService,
    @InjectRepository(RefreshSessionEntity)
    private readonly sessionsRepository: Repository<RefreshSessionEntity>,
  ) {
    const ttlInput = this.configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
      DEFAULT_REFRESH_TTL,
    );
    this.refreshTtlMs = durationStringToMs(
      ttlInput ?? DEFAULT_REFRESH_TTL,
      7 * 24 * 60 * 60 * 1000,
    );

    const maxLifetimeInput = this.configService.get<string>(
      'JWT_REFRESH_MAX_LIFETIME',
      DEFAULT_REFRESH_MAX_LIFETIME,
    );
    this.refreshMaxLifetimeMs = durationStringToMs(
      maxLifetimeInput ?? DEFAULT_REFRESH_MAX_LIFETIME,
      30 * 24 * 60 * 60 * 1000,
    );
  }

  async issue(
    user: SafeUser,
    metadata?: RefreshTokenMetadata,
    sessionId?: string,
  ): Promise<{ token: string; expiresAt: Date; session: RefreshSessionSnapshot }> {
    const token = randomBytes(48).toString('base64url');
    const tokenHash = this.hashToken(token);
    const now = new Date();
    const expiresWithinTtl = new Date(now.getTime() + this.refreshTtlMs);

    let session: RefreshSessionEntity;
    if (sessionId) {
      const existing = await this.sessionsRepository.findOne({
        where: { sessionId, userId: user.id },
      });
      if (!existing) {
        throw new TokenErrorException(
          'REFRESH_TOKEN_INVALID',
          'Session could not be continued',
        );
      }
      session = existing;
      session.metadata = metadata ?? session.metadata;
      if (!session.familyId) {
        session.familyId = randomUUID();
      }
      if (!session.maxExpiresAt) {
        const base = session.createdAt ?? now;
        session.maxExpiresAt = new Date(
          base.getTime() + this.refreshMaxLifetimeMs,
        );
      }
      if (session.maxExpiresAt.getTime() < now.getTime()) {
        await this.sessionsRepository.delete(session.sessionId);
        throw new TokenErrorException(
          'REFRESH_TOKEN_EXPIRED',
          'Session maximum lifetime exceeded',
        );
      }
    } else {
      session = this.sessionsRepository.create({
        userId: user.id,
        userSnapshot: user,
        metadata,
        createdAt: now,
        familyId: randomUUID(),
        maxExpiresAt: new Date(now.getTime() + this.refreshMaxLifetimeMs),
      });
    }

    session.createdAt ??= now;
    session.tokenHash = tokenHash;
    session.updatedAt = now;
    session.maxExpiresAt ??= new Date(
      session.createdAt.getTime() + this.refreshMaxLifetimeMs,
    );
    const expiresAt = expiresWithinTtl.getTime() > session.maxExpiresAt.getTime()
      ? new Date(session.maxExpiresAt)
      : expiresWithinTtl;
    session.expiresAt = expiresAt;
    session.userSnapshot = user;

    const saved = await this.sessionsRepository.save(session);

    return {
      token,
      expiresAt,
      session: this.toSnapshot(saved),
    };
  }

  async consume(refreshToken: string): Promise<RefreshSessionSnapshot> {
    const { session } = await this.findValidRecord(refreshToken);
    session.tokenHash = null;
    session.updatedAt = new Date();
    const saved = await this.sessionsRepository.save(session);
    return this.toSnapshot(saved);
  }

  async revoke(refreshToken: string): Promise<void> {
    const { session } = await this.findValidRecord(refreshToken);
    await this.sessionsRepository.delete(session.sessionId);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const result = await this.sessionsRepository.delete({ userId });
    return result.affected ?? 0;
  }

  async revokeSession(userId: string, sessionId: string): Promise<boolean> {
    const session = await this.sessionsRepository.findOne({
      where: { sessionId, userId },
    });
    if (!session) {
      return false;
    }
    await this.sessionsRepository.delete(sessionId);
    return true;
  }

  async listSessionsForUser(userId: string): Promise<RefreshSessionSnapshot[]> {
    const sessions = await this.sessionsRepository.find({
      where: { userId },
      order: { updatedAt: 'DESC' },
    });
    return sessions.map((session) => this.toSnapshot(session));
  }

  get refreshTtl(): number {
    return this.refreshTtlMs;
  }

  private async findValidRecord(refreshToken: string): Promise<{
    session: RefreshSessionEntity;
    tokenHash: string;
  }> {
    const hash = this.hashToken(refreshToken);
    const session = await this.sessionsRepository.findOne({
      where: { tokenHash: hash },
    });
    if (!session) {
      this.tokenEvents.logRefreshTokenFailure({
        code: 'REFRESH_TOKEN_INVALID',
        reason: 'Refresh token not found or already used',
        refreshTokenHash: hash,
      });
      throw new TokenErrorException('REFRESH_TOKEN_INVALID');
    }

    const now = Date.now();
    if (session.expiresAt.getTime() < now) {
      await this.sessionsRepository.delete(session.sessionId);
      this.tokenEvents.logRefreshTokenFailure({
        code: 'REFRESH_TOKEN_EXPIRED',
        reason: 'Refresh token expired',
        refreshTokenHash: hash,
      });
      throw new TokenErrorException('REFRESH_TOKEN_EXPIRED');
    }

    if (!session.maxExpiresAt) {
      session.maxExpiresAt = new Date(
        (session.createdAt ?? new Date()).getTime() + this.refreshMaxLifetimeMs,
      );
      await this.sessionsRepository.save(session);
    }

    if (session.maxExpiresAt.getTime() < now) {
      await this.sessionsRepository.delete(session.sessionId);
      this.tokenEvents.logRefreshTokenFailure({
        code: 'REFRESH_TOKEN_EXPIRED',
        reason: 'Session maximum lifetime exceeded',
        refreshTokenHash: hash,
      });
      throw new TokenErrorException('REFRESH_TOKEN_EXPIRED');
    }

    return { session, tokenHash: hash };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
  private toSnapshot(record: RefreshSessionEntity): RefreshSessionSnapshot {
    return {
      sessionId: record.sessionId,
      familyId: record.familyId,
      user: record.userSnapshot,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      expiresAt: record.expiresAt,
      maxExpiresAt: record.maxExpiresAt,
      metadata: record.metadata,
    };
  }

}
