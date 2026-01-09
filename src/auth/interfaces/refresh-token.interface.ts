import { SafeUser } from '../../users/users.service';

export interface RefreshTokenMetadata {
  deviceId?: string;
  deviceName?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface RefreshTokenRecord {
  tokenHash: string;
  user: SafeUser;
  createdAt: Date;
  expiresAt: Date;
  metadata?: RefreshTokenMetadata;
}
