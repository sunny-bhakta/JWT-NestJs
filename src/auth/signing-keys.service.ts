import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface SigningKeyConfig {
  id: string;
  secret: string;
  primary?: boolean;
}

export interface SigningKey {
  id: string;
  secret: string;
}

@Injectable()
export class SigningKeysService {
  private readonly keys = new Map<string, SigningKey>();
  private readonly activeKeyId: string;

  constructor(private readonly configService: ConfigService) {
    const { keys, activeKeyId } = this.loadKeysFromConfig();
    console.log('Loaded signing keys:', keys.map(k => k.id + '::' + k.secret));
    if (!keys.length) {
      throw new Error('No signing keys configured');
    }

    keys.forEach((key) => this.keys.set(key.id, { id: key.id, secret: key.secret }));
    this.activeKeyId = activeKeyId ?? keys[0].id;
  }

  getActiveKey(): SigningKey {
    return this.getKeyById(this.activeKeyId);
  }

  getKeyById(id?: string): SigningKey {
    if (!id) {
      return this.getActiveKey();
    }

    const key = this.keys.get(id);
    if (!key) {
      throw new Error(`Signing key with id "${id}" was not found`);
    }
    return key;
  }

  getAllKeyIds(): string[] {
    return Array.from(this.keys.keys());
  }

  private loadKeysFromConfig(): { keys: SigningKeyConfig[]; activeKeyId?: string } {
    const keysetRaw = this.configService.get<string>('JWT_KEYSET');
    const legacySecret = this.configService.get<string>('JWT_ACCESS_SECRET');

    if (!keysetRaw) {
      if (!legacySecret) {
        throw new Error('JWT_ACCESS_SECRET is required when JWT_KEYSET is not provided');
      }
      return {
        keys: [
          {
            id: 'default-key',
            secret: legacySecret,
            primary: true,
          },
        ],
        activeKeyId: 'default-key',
      };
    }

    let parsed: SigningKeyConfig[];
    try {
      parsed = JSON.parse(keysetRaw);
    } catch (error) {
      throw new Error('JWT_KEYSET must be valid JSON array');
    }

    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error('JWT_KEYSET must contain at least one key');
    }

    parsed.forEach((key, index) => {
      if (!key.id || !key.secret) {
        throw new Error(`Signing key at index ${index} is missing id or secret`);
      }
    });

    const configuredActiveKeyId = this.configService.get<string>('JWT_ACTIVE_KEY_ID');
    const primaryKey = parsed.find((key) => key.primary) ?? parsed[0];
    const activeKeyId = configuredActiveKeyId ?? primaryKey.id;

    if (!parsed.some((key) => key.id === activeKeyId)) {
      throw new Error(`Active signing key id "${activeKeyId}" not found in JWT_KEYSET`);
    }

    return { keys: parsed, activeKeyId };
  }
}
