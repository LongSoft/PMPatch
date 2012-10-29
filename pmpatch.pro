TEMPLATE = app
CONFIG += console
CONFIG -= qt app_bundle
 
SOURCES += \
    main.c \
    patch.c \
    Tiano/TianoCompress.c \
    Tiano/TianoDecompress.c \
    LZMA/LzmaCompress.c \
    LZMA/LzmaDecompress.c \
    LZMA/Sdk/C/LzmaDec.c \
    LZMA/Sdk/C/LzmaEnc.c \
    LZMA/Sdk/C/LzFind.c

HEADERS += \
    patch.h \
    Tiano/TianoCompress.h \
    Tiano/TianoDecompress.h \ 
    LZMA/LzmaCompress.h \
    LZMA/LzmaDecompress.h \
    LZMA/UefiLzma.h