import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

//todo add db check in validate method
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('JWT_ACCESS_SECRET'),
      audience: configService.get<string>('JWT_AUDIENCE', 'jwt-nest-client'),
      issuer: configService.get<string>('JWT_ISSUER', 'jwt-nest-api'),
    });
  }

  validate(payload: JwtPayload) {
    return payload;
  }
}
