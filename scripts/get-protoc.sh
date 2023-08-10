# DO NOT EDIT! Manage by ms-go/tools
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS=linux
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS=osx
else
    echo unsupported OS: $OSTYPE
fi

TMPFILE=`mktemp`.zip

trap "rm -f $TMPFILE" EXIT

wget -O $TMPFILE https://github.com/protocolbuffers/protobuf/releases/download/v3.11.4/protoc-3.11.4-$OS-x86_64.zip

unzip -j $TMPFILE bin/protoc -d deps

unzip -o $TMPFILE 'include/*' -d deps

chmod +x deps/protoc
