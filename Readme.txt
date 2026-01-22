
This has been tested on ubuntu 16.04 LTS desktop edition (64 bit).

This command is for Ubuntu 16.04 or higher (for older/32-bit Debian/Ubuntu releases; customize it for other distributions:
	sudo apt-get install gcc g++ binutils patch bzip2 flex make gettext \
	pkg-config unzip zlib1g-dev libc6-dev subversion libncurses5-dev gawk \
	sharutils curl libxml-parser-perl ocaml-nox ocaml ocaml-findlib \
	python-yaml libssl-dev libfdt-dev
	sudo apt-get install device-tree-compiler u-boot-tools

Note: In order to compile, you need to have an active internet connection.

build guide
1. run the command 'cd qsdk' to enter the build directory 
2. run the command 'make -f Makefile.cbt build_all_img’ to build firmware image
3. the new firmware image is created in directory "bin/ipq/board"

----------------------------------------------------------------------------------
package 'readline' guide:
1. How to install “readline-8.0” within the same building parameters
   1.1 if you want to modify readline, please make the patch file, then move it into qsdk/package/libs/readline/patches;
   1.2 if you want to change another version, pleae open qsdk/package/libs/readline/Makefile, then change below parameters to your wanted.
	PKG_VERSION
	PKG_HASH
   1.3 start to re-compile
	cd qsdk
        make package/libs/readline/clean V=s
        make package/libs/readline/compile V=s
2. build_log/readline.make.log is 'readline' build log file.
