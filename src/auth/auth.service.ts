import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  private readonly expiresIn: string;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    configService: ConfigService,
  ) {
    this.expiresIn = configService.get<string>('JWT_ACCESS_EXPIRES_IN', '15m');
  }

  async login(loginDto: LoginDto) {
    const user = await this.usersService.validateCredentials(
      loginDto.email,
      loginDto.password,
    );

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };

    const token = await this.jwtService.signAsync(payload);

    return {
      accessToken: token,
      tokenType: 'Bearer',
      expiresIn: this.expiresIn,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: user.roles,
      },
    };
  }
}
