# htool

`htool` provides a way to organize encrypted data that is accessible on any 
drive. By containerizing files based on their pre-existing metadata, encrypted 
data can be moved in an organized manner while retaining data security.

## Layout

Containers use a special layout to maintain the order of files contained within
them and to allow for operations like compaction and compression.

The following is a brief outline of how a container uses the 32KB it reserves,
in terms of bytes:
```
0-4 | version
4-20 | master salt
20-32 | master hash
32-52 | fat allocation table IV
52-68 | fat allocation table size
76- | fat allocation table entries
```

The first field is a version marker that informs the compatibility of a 
container with htool. This means older containers may not work with newer
versions of the tool to prevent corruption.

Containers are managed only by a master password that cannot be overwritten.
Alongside the hashed master pass is the salt, to be used for verification.

The rest of the reserved space is allocated to the file allocation table (FAT),
which gets encrypted also, to record files in the container.

## Commands

*All operations that in any way modify an existing container require its password.*

Make a new container `secrets` in the current working directory (CWD):
```
htool --mk secrets --pw 1234
```

Destroy the container `secrets` in the CWD:
```
htool --rm secrets --pw 1234
```

Write one or more files to `secrets`:
```
htool secrets --pw 1234 --store passwords.txt treasure_map.png
```

Load one or more files from `secrets`:
```
htool secrets --pw 1234 --load seed_phrase.txt
```

List out all the files in `secrets`:
```
htool secrets --pw 1234 --list
```

This dumps the following to a file in the CWD:
```
Filename           Original Size  Last Modified            
----------------------------------------------------------
passwords.txt      2714           1996-09-17 03:31:50      
treasure_map.png   163273         1996-09-17 07:14:57      
```

## Building

To build on any platform, you'll need
```
boost >= 1.8
cmake >= 3.15
openssl >= 3.6.0
```

and any compiler that supports C++20, i.e. clang 21.

Using CMake,
```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```
