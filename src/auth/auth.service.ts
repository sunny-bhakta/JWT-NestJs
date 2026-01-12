import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { Response } from 'express';
import type { CookieOptions } from 'express-serve-static-core';
import { UsersService, SafeUser } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { RefreshTokensService } from './refresh-tokens.service';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RefreshSessionSnapshot, RefreshTokenMetadata } from './interfaces/refresh-token.interface';
import { SigningKeysService } from './signing-keys.service';
import { durationStringToMs } from '../common/utils/duration.util';

export interface AuthTokensResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
  refreshTokenExpiresAt: string;
  refreshTokenExpiresIn: string;
  session: {
    sessionId: string;
    familyId: string;
    createdAt: string;
    updatedAt: string;
    expiresAt: string;
    maxExpiresAt: string;
    metadata?: RefreshTokenMetadata;
  };
  user: {
    id: string;
    email: string;
    name: string;
    roles: SafeUser['roles'];
    permissions: SafeUser['permissions'];
  };
}

@Injectable()
export class AuthService {
  private readonly expiresIn: string;
  private readonly refreshExpiresIn: string;
  private readonly accessTokenTtlMs: number;
  private readonly cookiesEnabled: boolean;
  private readonly cookieDomain?: string;
  private readonly cookiePath: string;
  private readonly cookieSameSite: CookieOptions['sameSite'];
  private readonly cookieSecure: boolean;
  private readonly accessTokenCookieName: string;
  private readonly refreshTokenCookieName: string;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly refreshTokensService: RefreshTokensService,
    private readonly signingKeysService: SigningKeysService,
    configService: ConfigService,
  ) {
    const accessTtlInput = configService.get<string>(
      'JWT_ACCESS_EXPIRES_IN',
      '15m',
    );
    this.expiresIn = accessTtlInput;
    this.accessTokenTtlMs = durationStringToMs(accessTtlInput, 15 * 60 * 1000);
    this.refreshExpiresIn = configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
      '7d',
    );
    this.cookiesEnabled = this.parseBoolean(
      configService.get<string>('AUTH_COOKIES_ENABLED'),
      false,
    );
    this.cookieDomain = configService.get<string>('AUTH_COOKIE_DOMAIN');
    this.cookiePath = configService.get<string>('AUTH_COOKIE_PATH', '/');
    this.cookieSameSite = this.parseSameSiteOption(
      configService.get<string>('AUTH_COOKIE_SAME_SITE', 'lax'),
    );
    this.cookieSecure = this.parseBoolean(
      configService.get<string>('AUTH_COOKIE_SECURE'),
      process.env.NODE_ENV === 'production',
    );
    this.accessTokenCookieName = configService.get<string>(
      'ACCESS_TOKEN_COOKIE_NAME',
      'access_token',
    );
    this.refreshTokenCookieName = configService.get<string>(
      'REFRESH_TOKEN_COOKIE_NAME',
      'refresh_token',
    );
  }

  async login(
    loginDto: LoginDto,
    metadata?: RefreshTokenMetadata,
  ): Promise<AuthTokensResponse> {
    const user = await this.usersService.validateCredentials(
      loginDto.email,
      loginDto.password,
    );

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.buildAuthResponse(user, {
      metadata: {
        deviceId: metadata?.deviceId ?? loginDto.deviceId,
        deviceName: metadata?.deviceName ?? loginDto.deviceName,
        ipAddress: metadata?.ipAddress,
        userAgent: metadata?.userAgent,
      },
    });
  }

  async refresh(refreshTokenDto: RefreshTokenDto): Promise<AuthTokensResponse> {
    const session = await this.refreshTokensService.consume(
      refreshTokenDto.refreshToken,
    );

    return this.buildAuthResponse(session.user, {
      sessionId: session.sessionId,
      metadata: session.metadata,
    });
  }

  async logout(refreshTokenDto: RefreshTokenDto) {
    await this.refreshTokensService.revoke(refreshTokenDto.refreshToken);
    return { success: true };
  }

  async listSessions(userId: string) {
    return this.refreshTokensService.listSessionsForUser(userId);
  }

  async revokeSession(userId: string, sessionId: string) {
    const success = await this.refreshTokensService.revokeSession(
      userId,
      sessionId,
    );

    if (!success) {
      throw new NotFoundException('Session not found');
    }

    return { success: true };
  }

  async revokeAllSessions(userId: string) {
    const revoked = await this.refreshTokensService.revokeAllForUser(userId);
    return { success: true, revoked };
  }

  private async buildAuthResponse(
    user: SafeUser,
    options: {
      sessionId?: string;
      metadata?: RefreshTokenMetadata;
    } = {},
  ): Promise<AuthTokensResponse> {
    const { sessionId, metadata } = options;
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
    };

    const signingKey = this.signingKeysService.getActiveKey();
    console.log('Using signing key:', signingKey.id);
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: signingKey.secret,
        keyid: signingKey.id,
      }),
      this.refreshTokensService.issue(user, metadata, sessionId),
    ]);

    return {
      accessToken,
      refreshToken: refreshToken.token,
      tokenType: 'Bearer',
      expiresIn: this.expiresIn,
      refreshTokenExpiresAt: refreshToken.expiresAt.toISOString(),
      refreshTokenExpiresIn: this.refreshExpiresIn,
      session: this.serializeSession(refreshToken.session),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: user.roles,
        permissions: user.permissions,
      },
    };
  }

  attachAuthCookies(res: Response, tokens: AuthTokensResponse) {
    if (!this.cookiesEnabled) {
      return;
    }

    const baseOptions = this.getCookieBaseOptions();
    res.cookie(this.accessTokenCookieName, tokens.accessToken, {
      ...baseOptions,
      maxAge: this.accessTokenTtlMs,
    });

    res.cookie(this.refreshTokenCookieName, tokens.refreshToken, {
      ...baseOptions,
      maxAge: this.refreshTokensService.refreshTtl,
    });
  }

  clearAuthCookies(res: Response) {
    if (!this.cookiesEnabled) {
      return;
    }

    const baseOptions = this.getCookieBaseOptions();
    res.clearCookie(this.accessTokenCookieName, baseOptions);
    res.clearCookie(this.refreshTokenCookieName, baseOptions);
  }

  private getCookieBaseOptions(): CookieOptions {
    return {
      httpOnly: true,
      secure: this.cookieSecure,
      sameSite: this.cookieSameSite,
      domain: this.cookieDomain,
      path: this.cookiePath,
    };
  }

  private parseSameSiteOption(
    value?: string,
  ): CookieOptions['sameSite'] {
    if (!value) {
      return 'lax';
    }

    const normalized = value.toLowerCase();
    if (['lax', 'strict', 'none'].includes(normalized)) {
      return normalized as CookieOptions['sameSite'];
    }

    if (normalized === 'true' || normalized === 'false') {
      return normalized === 'true';
    }

    return 'lax';
  }

  private parseBoolean(value: string | undefined, fallback: boolean): boolean {
    if (value === undefined || value === null) {
      return fallback;
    }

    return value.toLowerCase() === 'true';
  }

  private serializeSession(session: RefreshSessionSnapshot) {
    return {
      sessionId: session.sessionId,
      familyId: session.familyId,
      createdAt: session.createdAt.toISOString(),
      updatedAt: session.updatedAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      maxExpiresAt: session.maxExpiresAt.toISOString(),
      metadata: session.metadata,
    };
  }
}
