#ifndef __GAME_NETWORK_H__
#define __GAME_NETWORK_H__

/* IPV4 address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* Packet identifiers */
enum EPacketType
{
    Invalid = -1,
    Welcome = 1,
    Auth = 2,
    Approved = 3,
    Ready = 4,
    Entities = 5,
    EntityDestroy = 6,
    GroupChange = 7,
    GroupDestroy = 8,
    RPCMessage = 9,
    EntityPosition = 10,
    ConsoleMessage = 11,
    ConsoleCommand = 12,
    Effect = 13,
    DisconnectReason = 14,
    Last = 15,
    Tick = 15
};

struct Vector3 {
    float x;
    float y;
    float z;
    Vector3(float _x, float _y, float _z) {
        x = _x;
        y = _y;
        z = _z;
    }
    Vector3() {
        x = y = z = 0;
    }
};

/* Rust packet */
struct CPacket {

    char unk_1[26];
    char id;

    int GetID() {
        int _id = unk_1[27] & 0xff;
        return (_id - 140);
    }

    bool IsValid() {
        return GetID() <= Tick && GetID() >= Welcome;
    }

    EPacketType GetType() {
        if (!IsValid())
            return Invalid;
        return (EPacketType)GetID();
    }

    char* GetTypeString() {
        switch (GetType()) {
        case Invalid:
            return "Invalid";
        case Welcome :
            return "Welcome";
        case Auth :
            return "Auth";
        case Approved :
            return "Approved";
        case Ready :
            return "Ready";
        case Entities :
            return "Entities";
        case EntityDestroy :
            return "EntityDestroy";
        case GroupChange:
            return "GroupChange";
        case GroupDestroy:
            return "GroupDestroy";
        case RPCMessage:
            return "RPCMessage";
        case EntityPosition:
            return "EntityPostion";
        case ConsoleMessage:
            return "ConsoleMessage";
        case ConsoleCommand:
            return "ConsoleCommand";
        case Effect:
            return "Effect";
        case DisconnectReason:
            return "DisconnectReason";
        case Tick:
            return "Tick";
        default:
            return "Unknown";
        }
    }
};

struct CEntityPositionPacket : CPacket {
    UINT32 entityID;
    Vector3 position;
    Vector3 rotation;
};

struct CRPCMessagePacket : CPacket {
    UINT32 entityID;
    UINT nameID;
    ULONG sourceConnection;
};
struct CInput {
    UINT64 buttons;
    Vector3 aim;
};


/* Decode rust encoded uint32 */
UINT32 decode_uint32(char* buf, int* advance_size) {
    UINT32 num = 0;
    *advance_size = 1;
    for (int i = 0; i < 5; i++)
    {
        int num1 = *buf & 0xFF;
        buf++;

        if (num1 < 0)
        {
            return -1;
        }
        if (i == 4 && (num1 & 240) != 0)
        {
            return -1;
        }
        if ((num1 & 128) == 0)
        {
            return num | num1 << (7 * i & 31);
        }
        num = num | (num1 & 127) << (7 * i & 31);
    }
    return -1;
}
/* Decode Rust encoded Vector3 */
Vector3 decode_vector3(char* buf, int* advance_size) {
    Vector3 ret(0.0f, 0.0f, 0.0f);
    int adv_size = 0;
    int size = decode_uint32(buf, &adv_size);
    buf += adv_size;
    *advance_size = size;
    char* end = buf + size;
    while (buf < end)
    {
        int num = *buf;
        buf++;
        if (num == -1)
        {
            return Vector3(-1.0f, -1.0f, -1.0f);
        }
        if (num == 0xD)
        {
            ret.x = *(float*)buf;
            buf += 4;
        }
        else if (num == 0x15)
        {
            ret.y = *(float*)buf;
            buf += 4;
        }
        else if (num == 0x1D)
        {
            ret.z = *(float*)buf;
            buf += 4;
        }
        else
        {
            printf("Decode_Vector: Failed, unexpected byte\n");
            return Vector3(-1.0f, -1.0f, -1.0f);
        }
    }

    return ret;
}

/* Decode Rust encoded uint64 */
UINT64 decode_uint64(char* buf, int* advance_size) {
    ULONG num = 0;
    for (int i = 0; i < 10; i++)
    {
        int num1 = *buf;
        buf++;

        if (num1 < 0)
        {
            return -1;
        }
        if (i == 9 && (num1 & 254) != 0)
        {
            return -1;
        }
        if ((num1 & 128) == 0)
        {
            return num | (long)num1 << (7 * i & 63);
        }
        num = num | (long)(num1 & 127) << (7 * i & 63);
    }
    return -1;
}

struct CTickPacket : CPacket {
    BYTE byte_10;
    BYTE byte_8;
    UINT64 buttons;
    BYTE byte_18;
    BYTE byte_13;
    float aimx;
    BYTE byte_21;
    float aimy;
    BYTE byte_29;
    float aimz;

    CInput DecodeInput() {
        CInput input;
        char* cur = (char*)this + 28;
        if (*cur == 0x0A) { //Decode input state

            // Find length of input state
            cur++;
            int adv_size = 0;
            int len = decode_uint32(cur, &adv_size);
            cur += adv_size;
            char* begin = cur;
            while (cur < cur + len) {
                if (*cur == 8) {
                    // Decode buttons
                    cur++;
                    input.buttons = decode_uint64(cur, &adv_size);
                    cur += adv_size;
                    printf("BUTTONS 0x%X", input.buttons);
                }
                else if (*cur == 18) {
                    // Decode aimangles
                    cur++;
                    input.aim = decode_vector3(cur, &adv_size);
                    cur += adv_size;
                    printf("AIM %f %f %f\n", input.aim.x, input.aim.y, input.aim.z);
                }
                else {
                    printf(" fin\n");

                    return input;
                }

                cur++;
            }
        }
        printf("byte is %x\n", *cur);
        return input;
    }
    Vector3 GetViewAngles() {

    }
};

#endif