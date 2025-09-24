package app.rbac

default allow = false

# input: { "user": "...", "action": "...", "resource": "..." }

allow {
  some r
  user_has_role(input.user, r)
  role_allows(r, input.action, input.resource)
}

user_has_role(user, role) {
  some i
  data.rbac.roleBindings[i].user == user
  role := data.rbac.roleBindings[i].roles[_]
}

role_allows(role, action, resource) {
  some p
  data.rbac.roles[role].permissions[p].action == action
  glob.match(data.rbac.roles[role].permissions[p].resource, ["*"], resource)
}
