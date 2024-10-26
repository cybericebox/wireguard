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

-- name: UpdateVPNClientBanStatus :exec
update vpn_clients
set banned     = $3,
    updated_at = now()
where user_id = $1
  and group_id = $2;

-- name: UpdateVPNClientBannedStatusByGroupID :exec
update vpn_clients
set banned     = $2,
    updated_at = now()
where group_id = $1;

-- name: UpdateVPNClientBannedStatusByUserID :exec
update vpn_clients
set banned     = $2,
    updated_at = now()
where user_id = $1;

-- name: DeleteVPNClient :exec
delete
from vpn_clients
where user_id = $1
  and group_id = $2;

-- name: DeleteVPNClientsByGroupID :exec
delete
from vpn_clients
where group_id = $1;

-- name: DeleteVPNClientsByUserID :exec
delete
from vpn_clients
where user_id = $1;