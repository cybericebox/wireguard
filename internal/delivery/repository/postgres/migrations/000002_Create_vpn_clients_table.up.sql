create table if not exists vpn_clients
(
    user_id         uuid not null,
    group_id        uuid not null,

    primary key (user_id, group_id),

    ip_address      cidr not null unique,
    public_key      varchar(44) not null unique,
    private_key     varchar(44) not null unique,
    laboratory_cidr cidr not null,

    banned          boolean     not null default false,

    updated_at      timestamptz,

    created_at      timestamptz not null default now()
);