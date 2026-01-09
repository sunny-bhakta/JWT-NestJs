import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, SecretOrKeyProvider } from 'passport-jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { SigningKeysService } from './signing-keys.service';

//todo add db check in validate method
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    configService: ConfigService,
    signingKeysService: SigningKeysService,
  ) {
    const secretOrKeyProvider: SecretOrKeyProvider = (
      _request,
      rawJwtToken,
      done,
    ) => {
      try {
        const kid = JwtStrategy.extractKeyId(rawJwtToken);
        const key = signingKeysService.getKeyById(kid);
        done(null, key.secret);
      } catch (error) {
        const reason =
          error instanceof UnauthorizedException
            ? error
            : new UnauthorizedException((error as Error).message);
        done(reason, null);
      }
    };

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider,
      audience: configService.get<string>('JWT_AUDIENCE', 'jwt-nest-client'),
      issuer: configService.get<string>('JWT_ISSUER', 'jwt-nest-api'),
    });
  }

  validate(payload: JwtPayload) {
    return payload;
  }

  private static extractKeyId(rawJwtToken?: string): string | undefined {
    if (!rawJwtToken) {
      return undefined;
    }

    console.log('Raw JWT Token:', rawJwtToken);
    const [encodedHeader] = rawJwtToken.split('.');
    console.log('Encoded JWT Header:', encodedHeader);
    if (!encodedHeader) {
      throw new UnauthorizedException('Malformed JWT: missing header segment');
    }

    try {
      const headerJson = Buffer.from(encodedHeader, 'base64url').toString('utf8');
      const header = JSON.parse(headerJson) as { kid?: string };
      console.log('Decoded JWT Header JSON:', header);
      return header.kid;
    } catch {
      throw new UnauthorizedException('Malformed JWT header');
    }
  }
}
