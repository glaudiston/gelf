# init bloc
ARCH=$(uname -m || /usr/bin/uname -m) # fallback to the expected path of uname for when PATH is not set
ARCH=${ARCH:=x86_64} # fallback to the default most used arch currently
