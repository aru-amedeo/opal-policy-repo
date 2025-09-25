package authz

default allow := false

allow if {
  some rb
  binding := data.rbac.rolebindings[rb]
  subject_matches(binding.subjects, input.subject)
  scope_matches(binding.scope, input.action)
  role := data.rbac.roles[binding.role]
  rule_allows(role.rules, input.action)
}

# --- Subject matching: subject = {user, tenant}, supports "*" wildcards per field ---
subject_matches(subjects, subj) if {
  some i
  subject_fields_match(subjects[i], subj)
}

subject_fields_match(s, subj) if {
  field_match(s.user, subj.user)
  field_match(s.tenant, subj.tenant)
}

field_match(expected, actual) if {
  expected == "*"
}
field_match(expected, actual) if {
  expected == actual
}

# --- Scope matching (folder/project/region with "*" wildcard) ---
scope_matches(scope, act) if {
  scope_field_matches(scope.folder, act.folder)
  scope_field_matches(scope.project, act.project)
  scope_field_matches(scope.region, act.region)
}

scope_field_matches(expected, actual) if {
  expected == "*"
}
scope_field_matches(expected, actual) if {
  expected == actual
}

# --- Rule matching ---
rule_allows(rules, act) if {
  some i
  match_rule(rules[i], act)
}

match_rule(rule, act) if {
  list_has(rule.verbs, act.verb)
  list_has(rule.resourceProviders, coalesce(act.resourceProvider, ""))
  list_has(rule.resources, act.resource)
  resource_name_ok(rule, act)
}

# resourceName logic
resource_name_ok(_, act) if {
  not has_key(act, "resourceName")
}
resource_name_ok(rule, act) if {
  has_key(act, "resourceName")
  not has_key(rule, "resourceNames")
}
resource_name_ok(rule, act) if {
  has_key(act, "resourceName")
  has_key(rule, "resourceNames")
  list_has(rule.resourceNames, act.resourceName)
}

# --- Helpers ---
list_has(list, v) if {
  list[_] == "*"
}
list_has(list, v) if {
  list[_] == v
}
list_has(list, v) if {
  some i
  endswith(list[i], "/*")
  startswith(v, trim_suffix(list[i], "/*"))
}

has_key(obj, k) if {
  obj[k]
}

coalesce(x, y) = z if {
  x != null
  z := x
}
coalesce(x, y) = z if {
  x == null
  z := y
}
