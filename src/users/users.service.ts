import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { User } from './interfaces/user.interface';
import { PERMISSIONS } from 'src/utils/index.enum';

export type SafeUser = Omit<User, 'passwordHash'>;

@Injectable()
export class UsersService {
  private readonly users: User[] = [
    {
      id: '1',
      email: 'ada@example.com',
      name: 'Ada Lovelace',
      roles: ['user'],
      permissions: [PERMISSIONS.EDIT_PROFILE],
      passwordHash: bcrypt.hashSync('ChangeMe123!', 10),
    },
    {
      id: '2',
      email: 'admin@example.com',
      name: 'Grace Hopper',
      roles: ['admin'],
      permissions: [PERMISSIONS.VIEW_PROFILE],  
      passwordHash: bcrypt.hashSync('AdminPass123!', 10),
    },
  ];

  async findByEmail(email: string): Promise<User | undefined> {
    return this.users.find(
      (user) => user.email.toLowerCase() === email.toLowerCase(),
    );
  }

  async validateCredentials(
    email: string,
    password: string,
  ): Promise<SafeUser | undefined> {
    const user = await this.findByEmail(email);

    if (!user) {
      return undefined;
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return undefined;
    }

    const { passwordHash, ...safeUser } = user; 
    console.log('login:', safeUser);
    return safeUser;
  }
}
