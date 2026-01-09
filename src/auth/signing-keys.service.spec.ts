import { ConfigService } from '@nestjs/config';
import { SigningKeysService } from './signing-keys.service';

describe('SigningKeysService', () => {
  const buildService = (overrides: Record<string, string | undefined>) => {
    const configMock = {
      get: jest.fn((key: string) => overrides[key]),
    } as unknown as ConfigService;

    return new SigningKeysService(configMock);
  };

  it('uses the primary key as the active default', () => {
    const service = buildService({
      JWT_KEYSET: JSON.stringify([
        { id: 'key-old', secret: 'old-secret' },
        { id: 'key-new', secret: 'new-secret', primary: true },
      ]),
    });

    expect(service.getActiveKey()).toEqual({ id: 'key-new', secret: 'new-secret' });
  });

  it('honors JWT_ACTIVE_KEY_ID overrides', () => {
    const service = buildService({
      JWT_KEYSET: JSON.stringify([
        { id: 'key-a', secret: 'secret-a' },
        { id: 'key-b', secret: 'secret-b' },
      ]),
      JWT_ACTIVE_KEY_ID: 'key-b',
    });

    expect(service.getActiveKey()).toEqual({ id: 'key-b', secret: 'secret-b' });
  });

  it('falls back to JWT_ACCESS_SECRET when no keyset is provided', () => {
    const service = buildService({
      JWT_ACCESS_SECRET: 'legacy-secret',
    });

    expect(service.getActiveKey()).toEqual({ id: 'default-key', secret: 'legacy-secret' });
  });

  it('throws when an unknown key id is requested', () => {
    const service = buildService({
      JWT_KEYSET: JSON.stringify([{ id: 'only-key', secret: 'secret-value' }]),
    });

    expect(() => service.getKeyById('missing')).toThrow(
      'Signing key with id "missing" was not found',
    );
  });
});
