<?php

namespace Spatie\Permission\Traits;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\RoleTenantUserPivot;
use Spatie\Permission\Models\Tenant;

trait HasTenants
{
    use HasRoles;

    /**
     * A user may have multiple roles.
     */
    public function tenants(): BelongsToMany
    {
        $model = config('permission.models.tenant');
        $table = config('permission.table_names.role_tenant_user');
        $obj = $this->belongsToMany(
            $model,
            $table,
            'user_id',
            'tenant_id'
        )->withPivot('role_id')
            ->join('roles', 'role_tenant_user.role_id', '=', 'roles.id')
            ->select(
                'roles.name as pivot_role_name',
                config('permission.table_column.tenant.name'). ' as pivot_tenant_name'
            )
            ->using(config('permission.models.role_tenant_pivot'));

        return $obj;
    }

    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|\Spatie\Permission\Contracts\Permission $permission
     * @param string|\Spatie\Permission\Contracts\Tenant $tenant
     *
     * @return bool
     */
    public function hasPermissionToTenant($permission, $tenant): bool
    {
        if (is_string($permission)) {
            $permission = app(Permission::class)->findByName(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        return $this->hasDirectPermissionWithTenant($permission, $tenant) ||
            $this->hasPermissionViaRoleWithTenant($permission, $tenant);
    }

    /**
     * Determine if the user has the given permission.
     *
     * @param string|\Spatie\Permission\Contracts\Permission $permission
     * @param string|\Spatie\Permission\Contracts\Tenant $tenant
     *
     * @return bool
     */
    public function hasDirectPermissionWithTenant($permission, $tenant): bool
    {
        /*
         *  @toDo: Implement direct permission capabilities
         */

        return false;
    }

    /**
     * Determine if the user has, via roles, the given permission.
     *
     * @param \Spatie\Permission\Models\Permission $permission
     * @param string|\Spatie\Permission\Models\Tenant $tenant
     *
     * @return bool
     */
    protected function hasPermissionViaRoleWithTenant(Permission $permission, $tenant): bool
    {
         return $this->hasRoleWithTenant($permission->roles, $tenant);
    }

    /**
     * Determine if the user has (one of) the given role(s).
     *
     * @param string|\Illuminate\Database\Eloquent\Collection $role
     * @param string|\Spatie\Permission\Models\Tenant $tenant
     *
     * @return bool
     */
    public function hasRoleWithTenant($role, $tenant): bool
    {
        if ($role instanceof Collection) {
            foreach ($role as $k => $v) {
                $roles[] = $v->id;
            }
        }
        if (is_string($role) && is_string($tenant)) {
            return $this->tenants->where('pivot.role_name', $role)->where('pivot.tenant_name', $tenant)->isNotEmpty();
        } elseif (is_string($role) && $tenant instanceof Tenant) {
            return $this->tenants->where('pivot.role_name', $role)->where('pivot.tenant_id', $tenant->id)->isNotEmpty();
        } elseif (!empty($roles) && is_string($tenant)) {
            return $this->tenants->whereIn('pivot.role_id', $roles)->where('pivot.tenant_name', $tenant)->isNotEmpty();
        } elseif (!empty($roles) && $tenant instanceof Tenant) {
            return $this->tenants->whereIn('pivot.role_id', $roles)->where('pivot.tenant_id', $tenant->id)
                ->isNotEmpty();
        }

        return false;
    }

    public function checkViaRoleId($roleId)
    {
        return $this->belongsToMany(
            config('permission.models.tenant'),
            config('permission.table_names.role_tenant_user')
        )->withPivot('role_id')
            ->wherePivot('role_id', $roleId)
            ->using(config('permission.models.role_tenant_pivot'));
    }

    /**
     * Assign the given role to the user.
     *
     * @param array|int|\Spatie\Permission\Contracts\Role $roles
     * @param string|\Spatie\Permission\Contracts\Tenant $tenant
     *
     * @return $this
     */
    public function assignRoleToTenant($roles, $tenant)
    {
        if ($tenant instanceof Tenant) {
            $tenantId = $tenant->id;
        } elseif (is_numeric($tenant)) {
            $tenantId = $tenant;
        } elseif (is_string($tenant)) {
            $tenantId = $tenant;
        }
        $rtuPivot = new RoleTenantUserPivot();
        if (is_array($roles)) {
            foreach ($roles as $k => $v) {
                $rtuPivot->attach($this->id, $v->id, $tenantId);
            }
        } else {
            $rtuPivot->attach($this->id, $roles->id, $tenantId);
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke the given role and tenant from the user.
     *
     * @param array|int|\Spatie\Permission\Contracts\Role $role
     * @param string|\Spatie\Permission\Contracts\Tenant $tenant
     *
     */
    public function removeRoleFromTenant($role, $tenant)
    {
        $matches = [];
        if ($role instanceof Collection) {
            foreach ($role as $k => $v) {
                $roles[] = $v->id;
            }
        }

        if (is_string($role) && is_string($tenant)) {
            $matches = $this->tenants->where('pivot.role_name', $role)->where('pivot.tenant_id', $tenant);
        } elseif (is_string($role) && $tenant instanceof Tenant) {
            $matches = $this->tenants->where('pivot.role_name', $role)->where('pivot.tenant_id', $tenant->id);
        } elseif (!empty($roles) && is_string($tenant)) {
            $matches = $this->tenants->whereIn('pivot.role_id', $roles)->where('pivot.tenant_id', $tenant);
        } elseif (!empty($roles) && $tenant instanceof Tenant) {
            $matches = $this->tenants->whereIn('pivot.role_id', $roles)->where('pivot.tenant_id', $tenant->id);
        }

        foreach ($matches as $match) {
            $match->pivot->detach();
        }
    }
}
