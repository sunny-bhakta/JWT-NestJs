import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { JwtPayload } from './auth/interfaces/jwt-payload.interface';
import { Permissions } from './utils/permission.decorator';
import { PERMISSIONS } from './utils/index.enum';
import { PermissionGuard } from './utils/permission.guard';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req: { user: JwtPayload }) {
    return this.appService.getProfile(req.user);
  }

  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions(PERMISSIONS.VIEW_PROFILE)
  @Get('view-profile')
  getSecureData(@Request() req: { user: JwtPayload }) {
    return {
      message: 'This is view profile data.',
      user: this.appService.getProfile(req.user),
    };
  }

  @UseGuards(JwtAuthGuard, PermissionGuard)
  @Permissions(PERMISSIONS.EDIT_PROFILE)
  @Get('edit-profile')
  getEditData(@Request() req: { user: JwtPayload }) {
    return {
      message: 'This is edit profile data.',
      user: this.appService.getProfile(req.user),
    };
  }
}
