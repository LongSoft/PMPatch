PROJECT(PMPatch)
SET(PMPatch_SOURCES main.c patch.c Tiano/TianoCompress.c Tiano/TianoDecompress.c LZMA/LzmaCompress.c LZMA/LzmaDecompress.c LZMA/Sdk/C/LzmaDec.c LZMA/Sdk/C/LzmaEnc.c LZMA/Sdk/C/LzFind.c)
SET(PMPatch_HEADERS patch.h patch_int.h Tiano/TianoCompress.h Tiano/TianoDecompress.h LZMA/LzmaCompress.h LZMA/LzmaDecompress.h LZMA/UefiLzma.h)
ADD_EXECUTABLE(PMPatch ${PMPatch_SOURCES} ${PMPatch_HEADERS})