export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions?: string[];
  passwordHash: string;
}
