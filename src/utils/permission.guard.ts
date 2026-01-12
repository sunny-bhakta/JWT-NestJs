import { ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { PERMISSIONS } from "./index.enum";

@Injectable()
export class PermissionGuard {
    constructor(private readonly reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        const permissions = this.reflector.getAllAndOverride<PERMISSIONS[]>("permissions", [
            context.getHandler(),
            context.getClass(),
        ]);

        const request = context.switchToHttp().getRequest();
        console.log(request.user);
        const user = request.user as { permissions: PERMISSIONS[] } | undefined;
        // console.log("User Permissions:", user);
        return permissions.some(permission => user?.permissions?.includes(permission));
    }
}