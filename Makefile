export GOPATH=$(PWD)

depend:	
		@echo $(GOPATH)
		go get github.com/spacemonkeygo/spacelog
		go get github.com/spacemonkeygo/openssl
		go get github.com/fsnotify/fsnotify
		-patch -N -r /dev/null $(GOPATH)/src/github.com/spacemonkeygo/openssl/ctx.go $(GOPATH)/scripts/patch/openssl/ctx_mot.patch
		-patch -N -r /dev/null $(GOPATH)/src/github.com/spacemonkeygo/openssl/shim.c $(GOPATH)/scripts/patch/openssl/shim_mot_c.patch
		-patch -N -r /dev/null $(GOPATH)/src/github.com/spacemonkeygo/openssl/shim.h $(GOPATH)/scripts/patch/openssl/shim_mot_h.patch
		go get golang.org/x/crypto/sha3
		go get github.com/Ullaakut/nmap
		go get github.com/golang/protobuf/proto

build:		
		@echo $(GOPATH)
		go build motApp.go
		openssl dgst -sha3-256 motApp | awk '{print $$2}' > $(GOPATH)/Hashfile
		go build motPost.go

clean:	
		rm -f $(GOPATH)/motApp
		rm -f $(GOPATH)/motPost
		rm -f $(GOPATH)/Hashfile
