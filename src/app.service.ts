import { Injectable } from '@nestjs/common';
import { JwtPayload } from './auth/interfaces/jwt-payload.interface';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Secure JWT API is running';
  }

  getProfile(user: JwtPayload) {
    return {
      id: user.sub,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
    };
  }
}
