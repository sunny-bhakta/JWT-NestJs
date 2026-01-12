import { SafeUser } from '../../users/users.service';

export interface RefreshTokenMetadata {
  deviceId?: string;
  deviceName?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface RefreshSessionSnapshot {
  sessionId: string;
  familyId: string;
  user: SafeUser;
  createdAt: Date;
  updatedAt: Date;
  expiresAt: Date;
  maxExpiresAt: Date;
  metadata?: RefreshTokenMetadata;
}
