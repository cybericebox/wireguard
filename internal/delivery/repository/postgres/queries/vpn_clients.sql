-- name: CreateVpnClient :exec
insert into vpn_clients (id, ip_address, public_key, private_key, laboratory_cidr)
values ($1, $2, $3, $4, $5);

-- name: GetVPNClients :many
select id,
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
set banned = $2
where id = $1;

-- name: DeleteVPNClient :exec
delete
from vpn_clients
where id = $1;