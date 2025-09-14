/* This software is licensed under the MIT License: https://github.com/spacehuhntech/esp8266_deauther */

#pragma once

#include "Arduino.h"
#include "Accesspoints.h"
#include "Stations.h"
#include "Names.h"
#include "SSIDs.h"
#include "language.h"
#include "SimpleList.h"
#include <functional>

#define SCAN_MODE_OFF 0
#define SCAN_MODE_APS 1
#define SCAN_MODE_STATIONS 2
#define SCAN_MODE_ALL 3
#define SCAN_MODE_SNIFFER 4
#define SCAN_DEFAULT_TIME 15000
#define SCAN_DEFAULT_CONTINUE_TIME 10000
#define SCAN_PACKET_LIST_SIZE 64

extern Accesspoints accesspoints;
extern Stations     stations;
extern Names names;
extern SSIDs ssids;

extern uint8_t wifiMode;

extern void setWifiChannel(uint8_t ch, bool force);
extern bool appendFile(String path, String& buf);
extern bool writeFile(String path, String& buf);
extern void readFileToSerial(const String path);
extern String escape(String str);

struct client_info {
    uint8_t mac[6];
    uint32_t ip;
};

struct connection_info {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t seq;
    uint32_t ts;
    float    seq_rate;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint16_t src_port;
    uint16_t dst_port;
};

enum sniff_type { PKT_TCP, PKT_UDP, PKT_MDNS, PKT_ARP, PKT_BROADCAST, PKT_ENCRYPTED };

struct sniff_packet {
    sniff_type type;
    bool      broadcast;
    uint8_t   src_mac[6];
    uint8_t   dst_mac[6];
    uint32_t  src_ip;
    uint32_t  dst_ip;
    uint16_t  src_port;
    uint16_t  dst_port;
    uint8_t   ttl;
    uint16_t  ip_len;
    uint8_t   tcp_flags;
    uint32_t  tcp_seq;
    uint32_t  tcp_ack;
    uint8_t   frame_type;
    uint16_t  len;
};

#define SNIFF_PKT_BUF_SIZE 20

struct station_update {
    uint8_t mac_from[6];
    uint8_t mac_to[6];
    bool    to_broadcast;
    bool    from_broadcast;
};

#define STATION_UPDATE_BUF_SIZE 40

class Scan {
    public:
        Scan();
        ~Scan();

        void sniffer(uint8_t* buf, uint16_t len);
        void start(uint8_t mode, uint32_t time, uint8_t nextmode, uint32_t continueTime, bool channelHop, uint8_t channel);
        void start(uint8_t mode);

        void setup();
        void update();
        void stop();
        void save(bool force);
        void save(bool force, String filePath);

        void selectAll();
        void deselectAll();
        void printAll();
        void printSelected();

        uint8_t getPercentage();
        uint32_t getPackets(int i);
        uint32_t countAll();
        uint32_t countSelected();
        bool isScanning();
        bool isSniffing();

        void nextChannel();
        void setChannel(uint8_t newChannel);

        String getMode();
        double getScaleFactor(uint8_t height);
        uint32_t getMaxPacket();
        uint32_t getPacketRate();

        uint32_t getClientIP(uint8_t* mac);
        int clientCount();
        client_info getClient(int num);

        int connectionCount();
        connection_info getConnection(int num);

        void setSniffMac(const uint8_t* mac);
        int sniffPacketCount();
        sniff_packet getSniffPacket(int num);

        uint16_t deauths   = 0;
        uint16_t encrypted = 0;
        uint16_t packets   = 0;

        using stats_callback_t = std::function<void(uint16_t, uint16_t, uint16_t, uint8_t)>;
        void onSnifferStats(stats_callback_t cb);

    private:
        SimpleList<uint16_t>* list;                      // packet list
        SimpleList<client_info>* clients;                // mac-ip mapping
        SimpleList<connection_info>* connections;        // tracked TCP connections
        sniff_packet sniffPackets[SNIFF_PKT_BUF_SIZE];    // captured packets ring buffer
        SimpleList<station_update>* stationQueue;        // pending station updates
        int sniffPacketHead = 0;                          // next insert index
        int sniffPacketCnt  = 0;                          // number of stored packets
        uint8_t sniffMac[6] = {0};

        uint32_t sniffTime          = SCAN_DEFAULT_TIME; // how long the scan runs
        uint32_t snifferStartTime   = 0;                 // when the scan started
        uint32_t snifferOutputTime  = 0;                 // last info output (every 3s)
        uint32_t snifferChannelTime = 0;                 // last time the channel was changed
        uint32_t snifferPacketTime  = 0;                 // last time the packet rate was reseted (every 1s)
        uint32_t stationUpdateTime  = 0;                 // last station update processing

        uint8_t scanMode = 0;

        uint8_t scan_continue_mode = 0;                          // restart mode after scan stopped
        uint32_t continueTime      = SCAN_DEFAULT_CONTINUE_TIME; // time in ms to wait until scan restarts
        uint32_t continueStartTime = 0;                          // when scan restarted

        bool    channelHop      = true;
        uint8_t previousChannel = 1;   // channel before scan started
        uint16_t tmpDeauths     = 0;
        uint16_t tmpEncrypted   = 0;

        stats_callback_t statsCallback = nullptr;
        void outputStats();
        void processStationUpdates();

        bool apWithChannel(uint8_t ch);
        int findAccesspoint(uint8_t* mac);
        void updateClient(uint8_t* mac, uint32_t ip);
        void updateConnection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
                              uint32_t seq, uint8_t* src_mac, uint8_t* dst_mac);

        String FILE_PATH = "/scan.json";
};