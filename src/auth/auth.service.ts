import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService, SafeUser } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { RefreshTokensService } from './refresh-tokens.service';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RefreshTokenMetadata } from './interfaces/refresh-token.interface';

@Injectable()
export class AuthService {
  private readonly expiresIn: string;
  private readonly refreshExpiresIn: string;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly refreshTokensService: RefreshTokensService,
    configService: ConfigService,
  ) {
    this.expiresIn = configService.get<string>('JWT_ACCESS_EXPIRES_IN', '15m');
    this.refreshExpiresIn = configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
      '7d',
    );
  }

  async login(
    loginDto: LoginDto,
    metadata?: RefreshTokenMetadata,
  ) {
    const user = await this.usersService.validateCredentials(
      loginDto.email,
      loginDto.password,
    );

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.buildAuthResponse(user, {
      deviceId: metadata?.deviceId ?? loginDto.deviceId,
      deviceName: metadata?.deviceName ?? loginDto.deviceName,
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    });
  }

  async refresh(refreshTokenDto: RefreshTokenDto) {
    const user = await this.refreshTokensService.consume(
      refreshTokenDto.refreshToken,
    );

    return this.buildAuthResponse(user);
  }

  async logout(refreshTokenDto: RefreshTokenDto) {
    await this.refreshTokensService.revoke(refreshTokenDto.refreshToken);
    return { success: true };
  }

  private async buildAuthResponse(
    user: SafeUser,
    metadata?: RefreshTokenMetadata,
  ) {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload),
      this.refreshTokensService.issue(user, metadata),
    ]);

    return {
      accessToken,
      refreshToken: refreshToken.token,
      tokenType: 'Bearer',
      expiresIn: this.expiresIn,
      refreshTokenExpiresAt: refreshToken.expiresAt.toISOString(),
      refreshTokenExpiresIn: this.refreshExpiresIn,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: user.roles,
      },
    };
  }
}
