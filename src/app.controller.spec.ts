import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { JwtPayload } from './auth/interfaces/jwt-payload.interface';

describe('AppController', () => {
  let appController: AppController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
    }).compile();

    appController = app.get<AppController>(AppController);
  });

  describe('root', () => {
    it('should return a health message', () => {
      expect(appController.getHello()).toBe('Secure JWT API is running');
    });
  });

  describe('profile', () => {
    it('should map payload to profile shape', () => {
      const payload: JwtPayload = {
        sub: '1',
        email: 'ada@example.com',
        roles: ['user'],
        aud: 'client',
        iss: 'api',
      };

      expect(appController.getProfile({ user: payload })).toEqual({
        id: '1',
        email: 'ada@example.com',
        roles: ['user'],
      });
    });
  });
});
