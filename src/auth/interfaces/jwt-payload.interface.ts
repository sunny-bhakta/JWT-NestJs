export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  aud?: string;
  iss?: string;
  iat?: number;
  exp?: number;
}
