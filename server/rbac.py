"""Role-based access control for SecureChat."""

ROLE_USER = 'user'
ROLE_MODERATOR = 'moderator'
ROLE_MASTER_ADMIN = 'master_admin'

VALID_ROLES = {ROLE_USER, ROLE_MODERATOR, ROLE_MASTER_ADMIN}
ASSIGNABLE_ROLES = {ROLE_USER, ROLE_MODERATOR}

MASTER_ADMIN_USERNAME = 'admin'


def normalize_role(role):
    if not role:
        return ROLE_USER
    r = str(role).strip().lower()
    if r in ('admin', 'master', 'masteradmin', 'master_admin'):
        return ROLE_MASTER_ADMIN
    if r == 'moderator':
        return ROLE_MODERATOR
    return ROLE_USER


def is_master_admin(role):
    return normalize_role(role) == ROLE_MASTER_ADMIN


def is_moderator_or_above(role):
    r = normalize_role(role)
    return r in (ROLE_MODERATOR, ROLE_MASTER_ADMIN)


def can_manage_users(role):
    return is_master_admin(role)


def can_moderate_messages(role):
    return is_moderator_or_above(role)


def permissions_for_role(role):
    r = normalize_role(role)
    return {
        'role': r,
        'can_chat': True,
        'can_moderate': can_moderate_messages(r),
        'can_admin': can_manage_users(r),
        'can_assign_roles': can_manage_users(r),
        'can_delete_users': can_manage_users(r),
    }
