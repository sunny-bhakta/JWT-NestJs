import { SetMetadata } from "@nestjs/common";
import { PERMISSIONS } from "./index.enum";

export const Permissions = (...permissions: PERMISSIONS[]) => SetMetadata("permissions", permissions);