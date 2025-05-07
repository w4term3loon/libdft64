# Dependencies:
# sudo apt-get install gcc-multilib g++-multilib

CC=clang
CXX=clang++

LIBDFT_SRC			= src
LIBDFT_TOOL			= tools
# LIBDFT_TAG_FLAGS	?= -DLIBDFT_TAG_TYPE=libdft_tag_uint8

.PHONY: all
all: dftsrc tool #test

.PHONY: dftsrc mytool
dftsrc: $(LIBDFT_SRC)
	cd $< && CPPFLAGS=$(CPPFLAGS) DFTFLAGS=$(LIBDFT_TAG_FLAGS) make

tool: $(LIBDFT_TOOL)
	# cd $< && TARGET=ia32 CPPFLAGS=$(CPPFLAGS) DFTFLAGS=$(LIBDFT_TAG_FLAGS) make
	cd $< && TARGET=intel64 CPPFLAGS=$(CPPFLAGS) DFTFLAGS=$(LIBDFT_TAG_FLAGS) make

docker: Dockerfile
	docker build --platform linux/amd64 -t libdft-image:latest .

.PHONY: clean
clean:
	cd $(LIBDFT_SRC) && make clean
	cd $(LIBDFT_TOOL) && make clean
	@echo "Removing libdft-image:latest docker image..."
	-docker rmi libdft-image:latest || true

distclean: clean
	@echo "Attempting to remove base image ubuntu:20.04 if unused..."
	@echo "Note: This will only succeed if images are using ubuntu:20.04."
	-docker rmi ubuntu:20.04 || true
