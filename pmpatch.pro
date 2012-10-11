TEMPLATE = app
CONFIG += console
CONFIG -= qt app_bundle
 
SOURCES += \
    main.c \
    module.c \
    EDK2/CommonLib.c \
    EDK2/Decompress.c \
    EDK2/EfiCompress.c \
    EDK2/EfiUtilityMsgs.c \
    EDK2/TianoCompress.c

HEADERS += \
    module.h \
    EDK2/BaseTypes.h \
    EDK2/BuildVersion.h \ 
    EDK2/CommonLib.h \
    EDK2/Compress.h \
    EDK2/Decompress.h \
    EDK2/EfiCompress.h \
    EDK2/EfiUtilityMsgs.h \
    EDK2/UefiBaseTypes.h \
    EDK2/ProcessorBind.h
 