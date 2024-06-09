sqlcGenerate:
	docker run --rm -v ./internal/delivery/repository/postgres:/src -w /src sqlc/sqlc generate

addMigration:
	migrate create -ext sql -dir internal/delivery/repository/postgres/migrations -seq $(name)

buildAndPush:
	docker build -f deploy/Dockerfile . -t cybericebox/wireguard:$(tag) && docker push cybericebox/wireguard:$(tag)

protoCompile:
	docker run --rm -v ./pkg/controller/grpc/protobuf:/app -w /app --platform=linux/amd64 cybericebox/proto-compiler