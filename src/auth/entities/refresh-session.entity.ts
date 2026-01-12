import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';
import type { RefreshTokenMetadata } from '../interfaces/refresh-token.interface';
import type { SafeUser } from '../../users/users.service';

@Entity('refresh_sessions')
@Index('IDX_REFRESH_SESSION_TOKEN_HASH', ['tokenHash'], { unique: true })
export class RefreshSessionEntity {
  @PrimaryGeneratedColumn('uuid')
  sessionId!: string;

  @Column()
  userId!: string;

  @Column({ type: 'simple-json' })
  userSnapshot!: SafeUser;

  @Column({ type: 'text', nullable: true })
  tokenHash!: string | null;

  @Column({ type: 'text' })
  familyId!: string;

  @Column({ type: 'datetime' })
  createdAt!: Date;

  @Column({ type: 'datetime' })
  updatedAt!: Date;

  @Column({ type: 'datetime' })
  expiresAt!: Date;

  @Column({ type: 'datetime' })
  maxExpiresAt!: Date;

  @Column({ type: 'simple-json', nullable: true })
  metadata?: RefreshTokenMetadata;
}
