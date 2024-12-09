-- name: CreateVpnClient :exec
insert into vpn_clients (user_id, group_id, ip_address, public_key, private_key, laboratory_cidr)
values ($1, $2, $3, $4, $5, $6);

-- name: GetVPNClients :many
select user_id,
       group_id,
       ip_address,
       public_key,
       private_key,
       laboratory_cidr,
       banned,
       updated_at,
       created_at
from vpn_clients;

-- name: UpdateVPNClientsBanStatus :execrows
update vpn_clients
set banned = $1,
    updated_at = now()
where user_id = coalesce(sqlc.narg(user_id), user_id)
  and group_id = coalesce(sqlc.narg(group_id), group_id);

-- name: DeleteVPNClients :execrows
delete
from vpn_clients
where user_id = coalesce(sqlc.narg(user_id), user_id)
  and group_id = coalesce(sqlc.narg(group_id), group_id);