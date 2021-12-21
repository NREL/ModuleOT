depend:
	go mod vendor
	-patch -N -r /dev/null vendor/github.com/spacemonkeygo/openssl/ctx.go scripts/patch/openssl/ctx_mot.patch
	-patch -N -r /dev/null vendor/github.com/spacemonkeygo/openssl/shim.c scripts/patch/openssl/shim_mot_c.patch
	-patch -N -r /dev/null vendor/github.com/spacemonkeygo/openssl/shim.h scripts/patch/openssl/shim_mot_h.patch

build: depend
	mkdir -p bin
	go build -mod=vendor -a -ldflags="-s -w" -trimpath -o bin/motApp cmd/motApp/main.go
	openssl dgst -sha3-256 bin/motApp | awk '{print $$2}' > Hashfile
	go build -mod=vendor -a -ldflags="-s -w" -trimpath -o bin/motPost cmd/motPost/main.go

clean:
	rm -f bin/motApp
	rm -f bin/motPost
	rm -f Hashfile
