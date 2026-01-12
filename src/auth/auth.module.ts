import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { durationStringToSeconds } from '../common/utils/duration.util';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RefreshTokensService } from './refresh-tokens.service';
import { SigningKeysService } from './signing-keys.service';
import { TokenEventsService } from './token-events.service';

@Module({
  imports: [
    ConfigModule,
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const expiresIn = durationStringToSeconds(
          configService.get<string>('JWT_ACCESS_EXPIRES_IN', '15m'),
          15 * 60,
        );

        return {
          signOptions: {
            expiresIn,
            audience: configService.get<string>(
              'JWT_AUDIENCE',
              'jwt-nest-client',
            ),
            issuer: configService.get<string>('JWT_ISSUER', 'jwt-nest-api'),
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    JwtAuthGuard,
    RefreshTokensService,
    SigningKeysService,
    TokenEventsService,
  ],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}
