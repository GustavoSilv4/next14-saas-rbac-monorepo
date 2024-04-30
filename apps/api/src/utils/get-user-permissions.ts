import { defineAbilityFor } from "@saas/auth"
import { userSchema } from "@saas/auth/src/models/user"
import { Role } from "@saas/auth/src/roles"

export function getUserPermissions(userId: string, role: Role) {
  const authUser = userSchema.parse({
    id: userId,
    role: role,
  })

  const ability = defineAbilityFor(authUser)

  return ability
}
