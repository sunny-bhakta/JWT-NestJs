import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RefreshTokensService } from './refresh-tokens.service';
import { SafeUser } from '../users/users.service';
import { UnauthorizedException } from '@nestjs/common';

const userFixture: SafeUser = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Example User',
  roles: ['user'],
};

describe('RefreshTokensService', () => {
  let service: RefreshTokensService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        RefreshTokensService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockImplementation((key: string) => {
              if (key === 'JWT_REFRESH_EXPIRES_IN') {
                return '1h';
              }
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    service = moduleRef.get(RefreshTokensService);
  });

  it('issues and consumes refresh tokens', async () => {
    const { token } = await service.issue(userFixture);
    const result = await service.consume(token);

    expect(result.id).toBe(userFixture.id);
  });

  it('rejects reused or unknown tokens', async () => {
    const { token } = await service.issue(userFixture);
    await service.consume(token);

    await expect(service.consume(token)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('revokes all tokens for a user', async () => {
    await service.issue(userFixture);
    await service.issue(userFixture);

    const removed = await service.revokeAllForUser(userFixture.id);
    expect(removed).toBeGreaterThanOrEqual(2);
  });
});
