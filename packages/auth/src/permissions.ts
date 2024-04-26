import { AbilityBuilder } from '@casl/ability'

import { AppAbility } from '.'
import { User } from './models/user'
import { Role } from './roles'

type PermissionsByRole = (
  user: User,
  builder: AbilityBuilder<AppAbility>,
) => void

export const permissions: Record<Role, PermissionsByRole> = {
  ADMIN(_, { can }) {
    can('manage', 'all')
  },
  MEMBER(user, { can }) {
    // can('get', 'Billing')
    can(['create', 'get'], 'Project')
    can(['update', 'delete'], 'Project', { ownerId: user.id })
    can('delete', 'Organization', { ownerId: user.id })
  },
  BILLING() {},
}
