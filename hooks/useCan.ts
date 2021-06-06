import { useContext } from "react"
import { AuthContext } from "../src/contexts/AuthContext"
import { ValidadeUserPermissions } from "../utils/validadeUserPermissions"

type UseCanParams = {
  permissions?: string[];
  roles?: string[];
}

export function useCan({permissions, roles}: UseCanParams) {
  const { user, isAuthenticated } = useContext(AuthContext)

  if(!isAuthenticated) {
    return false
  }

  const userHasValidPermissions = ValidadeUserPermissions({
    user,
    permissions,
    roles
  })

  return userHasValidPermissions
}