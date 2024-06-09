create table if not exists vpn_clients
(
    id              uuid primary key,

    ip_address      inet        not null unique,
    public_key      varchar(44) not null unique,
    private_key     varchar(44) not null unique,
    laboratory_cidr inet        not null,

    banned          boolean     not null default false,

    updated_at      timestamptz,

    created_at      timestamptz not null default now()
);