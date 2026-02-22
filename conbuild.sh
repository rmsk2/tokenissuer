# Definitions
img=grap.de/tokenissuer:v1
binary=tokenissuer.tar
prog=tokenissuer

# cleanup
rm $binary
rm $prog

swag init -g main.go

# build binary
CGO_ENABLED=0 go build

# create image
myc=$(buildah from docker.io/library/alpine)
buildah copy $myc ./$prog /$prog
buildah config --entrypoint "/$prog" $myc
buildah config --port 5000 $myc
buildah commit $myc $img
buildah rm $myc
buildah push $img oci-archive:$binary:$img
buildah rmi $img

# Distribute image
scp $binary martin@debasus:$binary
scp $binary martin@desktop1:$binary
scp $binary martin@debasus2:$binary

