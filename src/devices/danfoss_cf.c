#include "decoder.h"

/*


NI       (3b) (network id)
FA       (1b) from address
TH       (1b) high byte of packet type
ZZ       (1b) always zero
TL       (1b) low byte of packet type
TA       (1b) to address
NN       (1b) from address as char
CS       (5b) control sum (unknow)
4X       (1b) controls heating operation


Packet examples:

# Type 0113, link check from remote control number 5, sent broadcast

NI NI NI FA TH ZZ TL TA ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
16 25 1c 05 01 00 13 ff 01 01 49 0c 00 f0 f0 72 f0 fe

# Type 030a, ack  to devices 5, 6 and 2

Sent by main unit to device (and back) to aknowledge receiving command.
Does not always confirm operation will proceed

NI NI NI FA TH ZZ TL TA ?? < {FA ^ TA | 0xD8} || {NI~TA ^ 0xFE}
16 25 1c 01 03 00 0a 02 db
16 25 1c 01 03 00 0a 03 da 
16 25 1c 01 03 00 0a 04 dd 
16 25 1c 01 03 00 0a 05 dc
16 25 1c 01 03 00 0a 06 df

16 25 1c 02 03 00 0a 01 db 
16 25 1c 03 03 00 0a 01 da 
16 25 1c 04 03 00 0a 01 dd 
16 25 1c 05 03 00 0a 01 dc 
16 25 1c 06 03 00 0a 01 df 

# type 4114 (conf undecoded) from devices 2, 4, 5, 6, goes immediately after link check

5 CS bytes contain control sum. Packets are not acknowledged by main unit when CS does not
match.

NI NI NI FA TH ZZ TL TA XX XX 4X ZZ ?? NN CS CS CS CS CS
16 25 1c 02 41 00 14 01 f0 25 8a 00 03 32 81 bc e9 e5 d8
16 25 1c 04 41 00 14 01 f0 25 0a 00 03 34 d8 4f cd 93 a0
16 25 1c 06 41 00 14 01 f0 25 8a 00 03 36 39 8d 7f 22 00

16 25 1c 05 41 00 14 01 f0 25 0a 00 03 35 b5 1f 5f cf 53
16 25 1c 05 41 00 14 01 f0 25 0a 00 03 35 b5 1f 5f cf 53
16 25 1c 05 41 00 14 01 f0 25 0a 00 03 35 b5 1f 5f cf 53
16 25 1c 05 41 00 14 01 f0 25 0a 00 03 35 b5 1f 5f cf 53
16 25 1c 05 41 00 14 01 f0 25 0a 00 03 35 b5 1f 5f cf 53
16 25 1c 05 41 00 14 01 f0 25 8a 00 03 35 b2 c8 3c 1f b0
16 25 1c 05 41 00 14 01 f0 25 8a 00 03 35 b2 c8 3c 1f b0
16 25 1c 05 41 00 14 01 f0 25 8a 00 03 35 b2 c8 3c 1f b0

# type 4124 (conf undecoded) response to 4114 notice difference in 4X btye 1a/9a similar
to 8d/0d in 4114 and 4117

NI NI NI FA TH ZZ TL TA XX XX 4X XX ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ
16 25 1c 01 41 00 24 05 f0 24 1a 01 00 00 00 00 00 00 00 00
16 25 1c 01 41 00 24 06 f0 24 9a 01 00 00 00 00 00 00 00 00
16 25 1c 01 41 00 24 05 f0 24 9a 01 00 00 00 00 00 00 00 00
16 25 1c 01 41 00 24 02 f0 24 9a 01 00 00 00 00 00 00 00 00


# Type 411C  report current temperature.
CH CL contains temperature in celsius times 100. 09 27 == 23.43 C

NN byte seems to be FA | 0x30 (which looks like string representation of it).

NI NI NI FA TH ZZ TL TA XX XX 4X ZZ NN XX XX ZZ CH CL XX XX XX XX CS CS CS CS CS
16 25 1c 05 41 00 1c 01 f0 81 92 00 35 91 03 00 09 27 14 11 14 14 48 6a 39 74 9f


# Type 4118 set temperature target.

CH CL contains temperature in celsius times 100.
4X byte controls heating -- 0E turns on, 8E turns off.
Last five bytes contain control sum

NI NI NI FA TH ZZ TL TA XX XX 4X ZZ NN ?? XX ?? CH CL CS CS CS CS CS
16 25 1c 06 41 00 18 01 f0 81 0e 00 36 01 03 01 09 60 88 a3 50 ce 19

# Type 4117 response from main unit during link/temp set

Note 8d/0d different in 4X byte similar to 4114 

NI NI NI FA TH ZZ TL TA XX XX 4X XX XX XX XX XX XX ?? ?? ?? ?? ??
16 25 1c 01 41 00 17 03 f0 80 0d 01 00 00 00 04 14 d1 2d 7c 
16 25 1c 01 41 00 17 04 f0 80 8d 01 00 00 00 04 14 35 10 c4 
16 25 1c 01 41 00 17 05 f0 80 8d 01 00 00 00 04 14 35 10 c4
16 25 1c 01 41 00 17 06 f0 80 0d 01 00 00 00 04 14 d1 2d 7c

# Type 210c when controller is put into link mode, broadcasting

NI NI NI FA TH ZZ TL TA XX XX XX
16 25 1c 01 21 00 0c ff 01 08 0b

*/


static int danfoss_cf_decode(r_device *decoder, bitbuffer_t *bitbuffer, unsigned row, unsigned bitpos)
{
    data_t *data;
    bitbuffer_t packet_bits = {0};
    uint8_t *b;
    unsigned int from_addr = 0, to_addr = 0, type = 0, temp_c = 0, net_id = 0;
    char *type_str = NULL;

    bitbuffer_manchester_decode(bitbuffer, row, bitpos, &packet_bits, 0);
    b = packet_bits.bb[0];
    
    net_id = b[0] << 16 | b[1] << 8 | b[2];
    from_addr = b[3];
    type = b[4] << 8 | b[6];
    to_addr = b[7];

    switch (type) {
    case 0x0113: type_str = "ping"; break;
    case 0x030a: type_str = "ack"; break;
    case 0x411C: type_str = "current_temp"; break;
    case 0x411E: type_str = "conf_1e"; break;

    case 0x4118: type_str = "target_temp"; break;

    // to be decoded
    case 0x4111: type_str = "conf_11"; break;
    case 0x4114: type_str = "conf_14"; break;
    case 0x4117: type_str = "conf_17"; break;
    case 0x4124: type_str = "conf_24"; break;

    case 0x210C: type_str = "link"; break;
    }

    if (type_str == NULL) {
      fprintf(stderr, "unknow packet type %04x\n", type);
      // bitbuffer_print(&packet_bits);
      return 0;
    }

    if (type == 0x4118) { // set temp
      temp_c = b[16] << 8 | b[17];
    } 
    if (type == 0x411C) { // set temp
      temp_c = b[16] << 8 | b[17];
    }

    /*
    fprintf(stderr, "known packet: %d of %d\n", packet_len, bitbuffer->bits_per_row[row]);
    bitbuffer_print(&packet_bits);
    if (packet_len < bitbuffer->bits_per_row[row]) {
        unsigned len = bitbuffer->bits_per_row[row] - packet_len;
        fprintf(stderr, "lefovers %d\n", len);
        bitbuffer_t tmp = {0};
        bitbuffer_extract_bytes(bitbuffer, row, packet_len, tmp.bb[row], len);

        memcpy(bitbuffer->bb[row], tmp.bb[row], (len + 7) / 8);
        bitbuffer->bits_per_row[row] = len;

        bitbuffer_print(bitbuffer);
    } */


    /* clang-format off */
    data = data_make(
            "model",            "",   DATA_STRING, "Danfoss CF",
            "net_id",           "",   DATA_FORMAT, "%06x",   DATA_INT,    net_id,
            "from_addr",        "",   DATA_FORMAT, "%x",     DATA_INT,    from_addr,
            "to_addr",          "",   DATA_COND, to_addr != 0, DATA_INT, to_addr,
            "packet_type",      "",             DATA_STRING, type_str,
            "temp_c",           "",   DATA_COND, temp_c != 0, DATA_INT, temp_c,
            NULL);
    /* clang-format on */

    decoder_output_data(decoder, data);
    return 1;
}

/** @sa danfoss_cf_decode() */
static int danfoss_cf_callback(r_device *decoder, bitbuffer_t *bitbuffer)
{
    // 99 99 99 99 55 aa aa a9
    uint8_t const preamble_pattern[5] = {0x99, 0x55, 0xAA, 0xAA, 0xA9};

    int row;
    unsigned bitpos = 0;
    int ret    = 0;
    int events = 0;

    fprintf(stderr, "Callback \n");
    bitbuffer_invert(bitbuffer);

    for (row = 0; row < bitbuffer->num_rows; ++row) {
        bitpos = 0;
        // Find a preamble with enough bits after it that it could be a complete packet
        while ((bitpos = bitbuffer_search(bitbuffer, row, bitpos,
                preamble_pattern, 5 * 8)) + 160 <=
                bitbuffer->bits_per_row[row]) {
            ret = danfoss_cf_decode(decoder, bitbuffer, row, bitpos + 5 * 8);
            if (ret > 0)
                events += ret;
            bitpos += 5 * 8;
        }
    }
    if (events == 0 && bitbuffer->bits_per_row[0] > 100) {
        fprintf(stderr, "unused packet bitpos %d %d\n", bitpos, bitbuffer->bits_per_row[0]);
        bitbuffer_print(bitbuffer);
    }


    return events > 0 ? events : ret;
}

static char *output_fields[] = {
        "model",
        "net_id",
        "from_addr",
        "to_addr",
        "packet_type",
        "temp_c",
        NULL,
};

r_device danfoss_cf = {
        .name        = "Danfoss CF Thermostat",
        .modulation  = FSK_PULSE_PCM,
        .short_width = 52,  // 12-13 samples @250k
        .long_width  = 52,  // FSK
        .reset_limit = 150, // Maximum gap size before End Of Message [us].
        .decode_fn   = &danfoss_cf_callback,
        .fields      = output_fields,
};
