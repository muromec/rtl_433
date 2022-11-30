#include "decoder.h"

/*

Protocol reverse-engineering for Danfoss CF2+ main unit and CF-RD ( 088U0214 )

https://store.danfoss.com/is/en/Climate-Solutions-for-heating/Hydronic-floor-heating/Service-kits-for-hydronic-floor-heatring/Floor-Heating-Controls%2C-Room-Thermostat-CF2%2C-Display/p/088U0214

Packets are manchester encoded with CRC8 as last byte.

All packets start with preamble of long string of 99 followed by 55 AA.
Basic frame structure:

NI       (4b) network id
FA       (1b) from address. main unit is 01, broadcast is FF, non-assigned 00
PT       (1b) packet type, can be data 41, ack 03, link announce 21, link join 61
PL       (2b) packet length in bytes, big endian
TA       (1b) to address.
CS       (1b) last byte is crc8 prime 1 with output masked by FF


# ACK packet

Sent by main unit to device (and back) to aknowledge receiving command.
Does not always confirm operation will proceed

NI NI NI NI FA PT PL PL TA CS
01 16 25 1c 01 03 00 0a 02 db
01 16 25 1c 01 03 00 0a 03 da
01 16 25 1c 01 03 00 0a 04 dd
01 16 25 1c 01 03 00 0a 05 dc
01 16 25 1c 01 03 00 0a 06 df

01 16 25 1c 02 03 00 0a 01 db
01 16 25 1c 03 03 00 0a 01 da
01 16 25 1c 04 03 00 0a 01 dd
01 16 25 1c 05 03 00 0a 01 dc
01 16 25 1c 06 03 00 0a 01 df


# Data packet

Packets with type 41 have a body of variable length with it's own checsum (or mac)
of 4 bytes.

F0       (1b) always f0
DI       (1b) direction 80 for downstream, 81 when talking to main unit
MT       (1b) higher byte alternates between 1 and 0 for unknown reason
              other bits denote message type

MAC      (4b) probavly a message authentication code of data bytes (starting from F0 or MI)
              does not change when TA changes, does change when DI changes.
              different networks have different value here for same data bytes

CS       (1b) CRC8 of whole packet (not just data)

NETWORK     FA PT PL PL TA|F0 DI MT ?? ?? ?? ?? ?? ??|   MAC     |CS
--------------------------------------------------------------------
01 15 f9 c2 01 41 00 17 04|f0 80 8d 01 00 00 00 04 14|4c 5f 6a 6b|7d
01 15 f9 c2 01 41 00 17 06|f0 80 8d 01 00 00 00 04 14|4c 5f 6a 6b|7f
01 15 f9 c2 01 41 00 17 02|f0 80 8d 01 00 00 00 04 14|4c 5f 6a 6b|7b
01 15 f9 c2 01 41 00 17 03|f0 80 0d 01 00 00 00 04 14|8e c6 7e 05|db

01 16 25 1c 01 41 00 17 03|f0 80 8d 01 00 00 00 04 14|35 10 c4 27|af
01 16 25 1c 01 41 00 17 08|f0 80 8d 01 00 00 00 04 14|35 10 c4 27|a4
01 16 25 1c 01 41 00 17 08|f0 80 8d 01 00 00 00 04 14|35 10 c4 27|a4



## Report current temperature

Example:
Packet header             |F0 DI MT    UU         |TEMP |           | MAC and CRC8
-----------------------------------------------------------------------------------
01 16 25 1c 08 41 00 1c 01 f0 81 12 00 35 91 03 00 08 d9 14 11 14 14 d2 c9 27 49 e0
01 16 25 1c 08 41 00 1c 01 f0 81 92 00 35 91 03 00 08 d3 14 11 14 14 92 41 46 2c a6
01 15 f9 c2 04 41 00 1c 01 f0 81 92 00 34 91 03 00 09 4a 14 11 14 14 ac 0e 32 56 4d
01 16 25 1c 08 41 00 1c 01 f0 81 12 00 35 91 03 00 08 d3 14 11 14 14 e0 74 6e f0 95


MT       (1b) high bit changes (sequence?) 7 lower bits message type 12
TEMP     (2b) Temperature observed by the sensor in celsium degrees
              08 d9 corresponds to 22.65 C
UU       (1b) mostly, but not always matches ASCII rendering of node address

Other bytes unknown

## Set target temperature

Packet header             |F0 DI MT    UU         |TEMP | MAC and CRC8
----------------------------------------------------------------------
01 16 25 1c 06 41 00 18 01 f0 81 0e 00 36 01 03 01 08 98 08 94 19 75 a5
01 16 25 1c 08 41 00 18 01 f0 81 8e 00 35 01 03 01 08 ca 67 e1 5c 7f 2f


MT       (1b) 7 lower bits contain message type 0E
TEMP     (2b) see above
UU       (1b) see above

Other bytes unknown

## Link test

Sent by remote controller when user presses main button to perform radio link test.
Outputs of main unit, controlled by remote will start blinking in re

Packet header             |F0 DI MT    UU               |TEMP |           | MAC and CRC8
-----------------------------------------------------------------------------------------
01 16 25 1c 08 41 00 1e 01 f0 81 94 00 35 a8 03 02 03 03 14 00 14 11 14 15 30 03 ea b9 8e
01 16 25 1c 08 41 00 1e 01 f0 81 14 00 35 a8 03 02 03 03 14 00 14 11 14 15 75 12 bc ff 4a
01 16 25 1c 06 41 00 1e 01 f0 81 94 00 36 a8 03 02 03 03 14 00 14 11 14 15 45 44 3c 25 fb
01 15 f9 c2 05 41 00 1e 01 f0 81 94 00 35 a8 03 02 03 03 14 00 14 11 14 15 15 b5 94 a7 71


## Target temperature from main unit

Sent in response to query from node (through MT 14)

Packet header             |      MT                     | TEMP         | MAC and CRC8
--------------------------------------------------------------------------------------
01 16 25 1c 01 41 00 1d 08 f0 80 13 01 00 00 03 e8 0b b8 08 98 00 00 15 2d bb 3a 12 85
01 16 25 1c 01 41 00 1d 08 f0 80 93 01 00 00 03 e8 0b b8 08 98 00 00 15 79 74 d0 86 e0
01 16 25 1c 01 41 00 1d 06 f0 80 93 01 00 00 03 e8 0b b8 08 34 00 00 15 4c 29 9e 91 73
01 15 f9 c2 01 41 00 1d 05 f0 80 13 01 00 00 03 e8 0b b8 09 c4 00 00 15 7d 89 10 0b 85
01 16 25 1c 01 41 00 1d 08 f0 80 13 01 00 00 03 e8 0b b8 08 34 00 00 15 29 93 9c 5c ed


MT       (1b) lower bits are message type 13


## Link mode session

When main unit is set into link mode and remote asks to join the network, following
exchange happens

Main unit announces broadcaset packet type 21

Network    |FA PT PL PL TA A1 A2 CS
-----------------------------------
01 16 25 1c 01 21 00 0c ff 01 08 0b

A1    (1b) address of main unit
A2    (1b) available address for node to join at

Remote sends broadcast request with no network it and no node it asking to join

Networ     |FA PT PL PL TA                            CS
--------------------------------------------------------
00 00 00 00 00 21 00 13 ff 01 01 49 0c 00 f0 f0 72 f0 f5

Main unit accepts new new into the network and repeats network id in message body
and sends data packet to that address, to which new node sends ACK

Network    |FA PT PL   |TA       A2 Network     CS
--------------------------------------------------
01 16 25 1c 01 61 00 11 00 01 03 08 01 16 25 1c 84

                        TA ?? ?? CS
01 16 25 1c 01 41 00 0c 08 72 04 e3

01 16 25 1c 08 03 00 0a 01 d1 - ACK to 1

01 16 25 1c 08 41 00 12 01 72 05 00 02 00 02 00 00 fc

Possibly output selection on main unit:
01 16 25 1c 01 41 00 0e 08 01 0c 01 00 9b
01 16 25 1c 08 03 00 0a 01 d1 - ACK
01 16 25 1c 01 41 00 0e 08 01 0c 00 10 8a
01 16 25 1c 08 03 00 0a 01 d1 - ACK to 1
01 16 25 1c 01 41 00 0e 08 01 0c 00 20 ba
01 16 25 1c 08 03 00 0a 01 d1 - ACK to 1
01 16 25 1c 01 41 00 0e 08 01 0c 00 30 aa
01 16 25 1c 08 03 00 0a 01 d1 - ACK to 1

New remote reports temperature
01 16 25 1c 08 41 00 1c 01 f0 81 92 00 35 a0 14 40 14 42 14 43 14 44 6a 16 f4 68 16
01 16 25 1c 01 03 00 0a 08 d1

Some unknown packets:
01 16 25 1c 01 41 00 1a 08 f0 80 90 01 00 00 00 19 ff 06 22 44 17 99 ab 17 d6
01 16 25 1c 08 03 00 0a 01 d1 - ACK to 1
01 16 25 1c 08 41 00 1f 01 f0 81 15 00 35 92 03 00 03 0f 09 5a 3e 14 11 14 14 f0 c4 69 d8 a7
01 16 25 1c 01 03 00 0a 08 d1 - ACK to 8
01 16 25 1c 01 41 00 17 08 f0 80 0d 01 00 00 00 04 14 d1 2d 7c 27 45
01 16 25 1c 08 03 00 0a 01 d1

*/


static int danfoss_cf_decode(r_device *decoder, bitbuffer_t *bitbuffer, unsigned row, unsigned bitpos)
{
    data_t *data;
    bitbuffer_t packet_bits = {0};
    uint8_t *b;
    unsigned int net_id = 0, temp_c = 0;
    uint8_t from_addr = 0, to_addr = 0, type = 0, data_type = 0, packet_len = 0, crc;

    char *type_str = NULL, *data_type_str = NULL;;
    char type_code_str[5] = {0, 0, 0, 0, 0};
    char data_type_code_str[5] = {0, 0, 0, 0, 0};

    bitpos = bitbuffer_manchester_decode(bitbuffer, row, bitpos, &packet_bits, 0);
    // smaller than smallest packet
    if (packet_bits.bits_per_row[0] < (8 * 10)) {
      return 0;
    }

    b = packet_bits.bb[0];

    packet_len = b[7];
    if (packet_bits.bits_per_row[0] / 8 != b[7]) {
      // packet length doesn't match packet size
      return 0;
    }

    crc = b[packet_len - 1] & 0xFF;
    if ((crc8(b, packet_len-1, 1, 0) ^ 0xFF) != crc) {
      return 0;
    }

    net_id = b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
    from_addr = b[4];
    type = b[5];
    to_addr = b[8];

    data_type = type == 0x41 ? (b[11] & 0x7F) : 0;

    sprintf(&type_code_str, "%02x", type);
    sprintf(&data_type_code_str, "%02x", data_type & 0x7F);

    switch (type) {
    case 0x01: type_str = "ping"; break;
    case 0x03: type_str = "ack"; break;
    case 0x21: type_str = "link"; break;
    case 0x41: type_str = "data"; break;
    case 0x61: type_str = "join"; break;
    default: type_str = &type_code_str;
    }

    switch(data_type) {
    case 0x0E: data_type_str = "set_temp"; break;
    case 0x12: data_type_str = "report_temp"; break;
    default: data_type_str = &data_type; break;
    }

    if (data_type == 0x0E) { // set temp
      temp_c = b[17] << 8 | b[18];
    }
    if (data_type == 0x12) { // set temp
      temp_c = b[17] << 8 | b[18];
    }

    /* clang-format off */
    data = data_make(
            "model",            "",   DATA_STRING, "Danfoss CF",
            "net_id",           "",   DATA_FORMAT, "%08x",   DATA_INT,    net_id,
            "from_addr",        "",   DATA_FORMAT, "%02x",     DATA_INT,    from_addr,
            "to_addr",          "",   DATA_FORMAT, "%02x",   DATA_INT,    to_addr,
            "packet_type",      "",             DATA_STRING, type_str,
            "data_type",      "",             DATA_STRING, data_type_str,
            "temp_c",           "",   DATA_COND, temp_c != 0, DATA_INT, temp_c,
            "mic",              "Integrity",    DATA_STRING, "CRC",
            NULL);
    /* clang-format on */

    decoder_output_data(decoder, data);
    return 1;
}

/** @sa danfoss_cf_decode() */
static int danfoss_cf_callback(r_device *decoder, bitbuffer_t *bitbuffer)
{
    // 99 99 99 99 55 aa
    uint8_t const preamble_pattern[6] = {0x99, 0x99, 0x99, 0x99, 0x55, 0xAA};

    int row;
    unsigned bitpos = 0;
    int ret    = 0;
    int events = 0;

    bitbuffer_invert(bitbuffer);

    for (row = 0; row < bitbuffer->num_rows; ++row) {
        bitpos = 0;
        // Find a preamble with enough bits after it that it could be a complete packet
        while ((bitpos = bitbuffer_search(bitbuffer, row, bitpos,
                preamble_pattern, 6 * 8)) + 160 <=
                bitbuffer->bits_per_row[row]) {
            ret = danfoss_cf_decode(decoder, bitbuffer, row, bitpos + 6 * 8);
            if (ret > 0)
                events += ret;
            bitpos += 6 * 8;
        }
    }
    if (decoder->verbose > 1 && events == 0 && bitbuffer->bits_per_row[0] > 100) {
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
        "data_type",
        "temp_c",
        "mic",
        NULL,
};

r_device danfoss_cf2 = {
        .name        = "Danfoss CF2 Thermostat",
        .modulation  = FSK_PULSE_PCM,
        .short_width = 52,  // 12-13 samples @250k
        .long_width  = 52,  // FSK
        .reset_limit = 150, // Maximum gap size before End Of Message [us].
        .decode_fn   = &danfoss_cf_callback,
        .fields      = output_fields,
};
