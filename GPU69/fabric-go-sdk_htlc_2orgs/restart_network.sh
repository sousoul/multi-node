cd fixtures/
docker-compose down
docker volume prune
docker-compose up -d
cd ..
go build # 修改链码需要每次编译fabric-go-sdk吗
#./fabric-go-sdk

