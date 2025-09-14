/* This software is licensed under the MIT License: https://github.com/spacehuhntech/esp8266_deauther */

#include "Scan.h"

#include "settings.h"
#include "wifi.h"

bool isZeroMac(const uint8_t* mac) {
    for (uint8_t i = 0; i < 6; i++)
        if (mac[i] != 0x00) return false;

    return true;
}

Scan::Scan() {
    list    = new SimpleList<uint16_t>;
    clients = new SimpleList<client_info>;
    connections = new SimpleList<connection_info>;
    sniffPackets = new SimpleList<sniff_packet>;
}

void Scan::sniffer(uint8_t* buf, uint16_t len) {
    if (!isSniffing()) return;

    packets++;

    if (len < 24) return;  // drop frames that are too short to have a valid MAC header

    uint16_t frameCtrl = buf[0] | (buf[1] << 8);
    uint8_t type       = (frameCtrl >> 2) & 0x3;
    uint8_t subtype    = (frameCtrl >> 4) & 0xF;
    uint8_t toFrom     = (frameCtrl >> 8) & 0x3;

    // resolve addresses
    uint8_t* addr1 = buf + 4;
    uint8_t* addr2 = buf + 10;
    uint8_t* addr3 = buf + 16;
    uint8_t* addr4 = nullptr;
    if (toFrom == 3) {
        if (len < 30) return;  // need fourth address
        addr4 = buf + 24;
    }

    uint8_t* macTo   = nullptr;
    uint8_t* macFrom = nullptr;
    switch (toFrom) {
        case 0: // RA/TA
            macTo   = addr1;
            macFrom = addr2;
            break;
        case 1: // RA/Address3
            macTo   = addr1;
            macFrom = addr3;
            break;
        case 2: // Address3/TA
            macTo   = addr3;
            macFrom = addr2;
            break;
        case 3: // Address3/Address4
            macTo   = addr3;
            macFrom = addr4;
            break;
    }

    if (!macTo || !macFrom) return;

    if (type == 0 && (subtype == 0x0C || subtype == 0x0A)) {  // deauth or disassoc
        tmpDeauths++;
        return;
    }

    // drop beacon frames, probe requests and probe responses
    if (type == 0 && (subtype == 0x08 || subtype == 0x04 || subtype == 0x05)) return;

    if (!macValid(macTo) || !macValid(macFrom)) return;
    bool toBroadcast   = macBroadcast(macTo);
    bool fromBroadcast = macBroadcast(macFrom);
    if (!toBroadcast && macMulticast(macTo)) return;
    if (!fromBroadcast && macMulticast(macFrom)) return;

    bool isBroadcast = toBroadcast || fromBroadcast;

    // filter for selected client
    bool hasFilter = !isZeroMac(sniffMac);
    if (hasFilter && memcmp(sniffMac, macTo, 6) != 0 && memcmp(sniffMac, macFrom, 6) != 0) return;

    sniff_packet sp{};
    sp.type      = PKT_BROADCAST;
    sp.broadcast = isBroadcast;
    memcpy(sp.src_mac, macFrom, 6);
    memcpy(sp.dst_mac, macTo, 6);
    sp.ip_len    = 0;
    sp.tcp_flags = 0;
    sp.tcp_seq   = 0;
    sp.tcp_ack   = 0;

    int accesspointNum = findAccesspoint(macFrom);

    if (accesspointNum >= 0) {
        stations.add(macTo, accesspoints.getID(accesspointNum));
    } else {
        accesspointNum = findAccesspoint(macTo);

        if (accesspointNum >= 0) {
            stations.add(macFrom, accesspoints.getID(accesspointNum));
        }
    }

        // parse payload for IP addresses
    if (frameCtrl & 0x4000) return; // encrypted, skip
    if (type == 2) { // data frame
        int hdrLen = 24;
        uint8_t toFrom = (frameCtrl >> 8) & 0x3;
        if (toFrom == 3) hdrLen = 30; // WDS
        if (subtype & 0x08) hdrLen += 2; // QoS data
        if (len <= hdrLen + 8) return;
        uint8_t* llc = buf + hdrLen;
        if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
            uint16_t ethertype = (llc[6] << 8) | llc[7];
            uint8_t* payload   = llc + 8;
            if (ethertype == 0x0800) { // IPv4
                if (len >= hdrLen + 8 + 20) {
                    uint8_t* iphdr = payload;
                    uint32_t src   = (iphdr[12] << 24) | (iphdr[13] << 16) | (iphdr[14] << 8) | iphdr[15];
                    uint32_t dst   = (iphdr[16] << 24) | (iphdr[17] << 16) | (iphdr[18] << 8) | iphdr[19];
                    updateClient(macFrom, src);
                    updateClient(macTo, dst);
                    sp.src_ip = src;
                    sp.dst_ip = dst;
                    sp.ttl    = iphdr[8];
                    sp.ip_len = (iphdr[2] << 8) | iphdr[3];

                    uint8_t proto = iphdr[9];
                    uint8_t ihl   = (iphdr[0] & 0x0F) * 4;
                    if ((proto == 6) && (len >= hdrLen + 8 + ihl + 20)) { // TCP
                        uint8_t* tcp      = payload + ihl;
                        uint16_t src_port = (tcp[0] << 8) | tcp[1];
                        uint16_t dst_port = (tcp[2] << 8) | tcp[3];
                        uint32_t seq      = (tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
                        uint32_t ack      = (tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8) | tcp[11];
                        uint8_t flags     = tcp[13];

                        updateConnection(src, dst, src_port, dst_port, seq, macFrom, macTo);

                        sp.type      = PKT_TCP;
                        sp.src_port  = src_port;
                        sp.dst_port  = dst_port;
                        sp.tcp_seq   = seq;
                        sp.tcp_ack   = ack;
                        sp.tcp_flags = flags;
                    } else if ((proto == 17) && (len >= hdrLen + 8 + ihl + 8)) { // UDP
                        uint8_t* udp      = payload + ihl;
                        uint16_t src_port = (udp[0] << 8) | udp[1];
                        uint16_t dst_port = (udp[2] << 8) | udp[3];
                        sp.type = (src_port == 5353 || dst_port == 5353) ? PKT_MDNS : PKT_UDP;
                        sp.src_port = src_port;
                        sp.dst_port = dst_port;
                        }
                    }
                } else if (ethertype == 0x0806) { // ARP
                    if (len >= hdrLen + 8 + 28) {
                        uint8_t* arp = payload;
                        uint8_t* smac = arp + 8;
                        uint8_t* sip  = arp + 14;
                        uint8_t* tmac = arp + 18;
                        uint8_t* tip  = arp + 24;
                        uint32_t s_ip = (sip[0] << 24) | (sip[1] << 16) | (sip[2] << 8) | sip[3];
                        uint32_t t_ip = (tip[0] << 24) | (tip[1] << 16) | (tip[2] << 8) | tip[3];
                        updateClient(smac, s_ip);
                        updateClient(tmac, t_ip);
                        sp.type   = PKT_ARP;
                        sp.src_ip = s_ip;
                        sp.dst_ip = t_ip;
                }
            }
        }
    }
    if (sniffPackets->size() >= SNIFF_PKT_BUF_SIZE) sniffPackets->shift();
    sniffPackets->add(sp);
}

int Scan::findAccesspoint(uint8_t* mac) {
    for (int i = 0; i < accesspoints.count(); i++) {
        if (memcmp(accesspoints.getMac(i), mac, 6) == 0) return i;
    }
    return -1;
}

void Scan::updateClient(uint8_t* mac, uint32_t ip) {
    if (!mac || !clients) return;
    for (int i = 0; i < clients->size(); i++) {
        client_info ci = clients->get(i);
        if (memcmp(ci.mac, mac, 6) == 0) {
            if (ci.ip != ip) {
                ci.ip = ip;
                clients->replace(i, ci);
            }
            return;
        }
    }
    client_info ci;
    memcpy(ci.mac, mac, 6);
    ci.ip = ip;
    clients->add(ci);
}
void Scan::updateConnection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
                            uint32_t seq, uint8_t* src_mac, uint8_t* dst_mac) {
    if (!connections) return;
    for (int i = 0; i < connections->size(); i++) {
        connection_info co = connections->get(i);
        if (co.src_ip == src_ip && co.dst_ip == dst_ip && co.src_port == src_port && co.dst_port == dst_port) {
            uint32_t dt = currentTime - co.ts;
            if (dt > 0) co.seq_rate = float(seq - co.seq) / float(dt);
            co.seq = seq;
            co.ts  = currentTime;
            if (src_mac) memcpy(co.src_mac, src_mac, 6);
            if (dst_mac) memcpy(co.dst_mac, dst_mac, 6);
            connections->replace(i, co);
            return;
        }
    }
    connection_info co = {0};
    co.src_ip   = src_ip;
    co.dst_ip   = dst_ip;
    co.src_port = src_port;
    co.dst_port = dst_port;
    co.seq      = seq;
    co.ts       = currentTime;
    co.seq_rate = 0;
    if (src_mac) memcpy(co.src_mac, src_mac, 6);
    if (dst_mac) memcpy(co.dst_mac, dst_mac, 6);
    connections->add(co);
}

uint32_t Scan::getClientIP(uint8_t* mac) {
    if (!mac || !clients) return 0;
    for (int i = 0; i < clients->size(); i++) {
        client_info ci = clients->get(i);
        if (memcmp(ci.mac, mac, 6) == 0) return ci.ip;
    }
    return 0;
}

int Scan::clientCount() {
    return clients ? clients->size() : 0;
}

client_info Scan::getClient(int num) {
    if (!clients || num < 0 || num >= clients->size()) {
        client_info empty = {{0}, 0};
        return empty;
    }
    return clients->get(num);
}

int Scan::connectionCount() {
    return connections ? connections->size() : 0;
}

connection_info Scan::getConnection(int num) {
    if (!connections || num < 0 || num >= connections->size()) {
        connection_info empty = {0};
        return empty;
    }
    return connections->get(num);
}

void Scan::setSniffMac(const uint8_t* mac) {
    if (mac) {
        memcpy(sniffMac, mac, 6);
    } else {
        memset(sniffMac, 0, 6);
    }
    if (sniffPackets) sniffPackets->clear();
}

int Scan::sniffPacketCount() {
    return sniffPackets ? sniffPackets->size() : 0;
}

sniff_packet Scan::getSniffPacket(int num) {
    if (!sniffPackets || num < 0 || num >= sniffPackets->size()) {
        sniff_packet empty = {PKT_BROADCAST, false};
        memset(empty.src_mac, 0, 6);
        memset(empty.dst_mac, 0, 6);
        empty.src_ip   = empty.dst_ip = 0;
        empty.src_port = empty.dst_port = 0;
        empty.ttl      = 0;
        empty.ip_len   = 0;
        empty.tcp_flags = 0;
        empty.tcp_seq   = 0;
        empty.tcp_ack   = 0;
        return empty;
    }
    return sniffPackets->get(num);
}

void Scan::start(uint8_t mode) {
    start(mode, sniffTime, scan_continue_mode, continueTime, channelHop, wifi_channel);
}

void Scan::start(uint8_t mode, uint32_t time, uint8_t nextmode, uint32_t continueTime, bool channelHop,
                 uint8_t channel) {
    if ((mode != SCAN_MODE_OFF) && channelHop && (scanMode == SCAN_MODE_OFF)) previousChannel = wifi_channel;
    if (mode != SCAN_MODE_OFF) stop();

    setWifiChannel(channel, true);
    Scan::continueStartTime  = currentTime;
    Scan::snifferPacketTime  = continueStartTime;
    Scan::snifferOutputTime  = continueStartTime;
    Scan::continueTime       = continueTime;
    Scan::sniffTime          = time;
    Scan::channelHop         = channelHop;
    Scan::scanMode           = mode;
    Scan::scan_continue_mode = nextmode;

    if ((sniffTime > 0) && (sniffTime < 1000)) sniffTime = 1000;

    // Serial.printf("mode: %u, time: %u, continue-mode: %u, continueTime: %u, channelHop: %u, channel: %u\r\n", mode,
    // time, scan_continue_mode, continueTime, channelHop, channel);

    /* AP Scan */
    if ((mode == SCAN_MODE_APS) || (mode == SCAN_MODE_ALL)) {
        // remove old results
        accesspoints.removeAll();
        stations.removeAll();
        // start AP scan
        prntln(SC_START_AP);
        WiFi.scanNetworks(true, true);
    }

    /* Station Scan */
    else if (mode == SCAN_MODE_STATIONS) {
        // reset sniff filter
        memset(sniffMac, 0, 6);
        // start station scan
        if (accesspoints.count() < 1) {
            start(SCAN_MODE_ALL);
            // Serial.println(str(SC_ERROR_NO_AP));
            return;
        }
        snifferStartTime = currentTime;
        prnt(SC_START_CLIENT);

        if (sniffTime > 0) prnt(String(sniffTime / 1000) + S);
        else prnt(SC_INFINITELY);

        if (!channelHop) {
            prnt(SC_ON_CHANNEL);
            prnt(wifi_channel);
        }
        prntln();

        // enable sniffer
        wifi::stopAP();
        wifi_promiscuous_enable(true);
    }

    else if (mode == SCAN_MODE_SNIFFER) {
        deauths          = tmpDeauths;
        tmpDeauths       = 0;
        snifferStartTime = currentTime;
        prnt(SS_START_SNIFFER);

        if (sniffTime > 0) prnt(String(sniffTime / 1000) + S);
        else prnt(SC_INFINITELY);
        prnt(SC_ON_CHANNEL);
        prntln(channelHop ? str(SC_ONE_TO) + (String)14 : (String)wifi_channel);

        // enable sniffer
        wifi::stopAP();
        wifi_promiscuous_enable(true);
    }

    /* Stop scan */
    else if (mode == SCAN_MODE_OFF) {
        wifi_promiscuous_enable(false);
        setWifiChannel(previousChannel, true);

        if (settings::getWebSettings().enabled) wifi::resumeAP();
        prntln(SC_STOPPED);
        save(true);

        if (scan_continue_mode != SCAN_MODE_OFF) {
            prnt(SC_RESTART);
            prnt(int(continueTime / 1000));
            prntln(SC_CONTINUE);
        }
    }

    /* ERROR */
    else {
        prnt(SC_ERROR_MODE);
        prntln(mode);
        return;
    }
}

void Scan::update() {
    if (scanMode == SCAN_MODE_OFF) {
        // restart scan if it is continuous
        if (scan_continue_mode != SCAN_MODE_OFF) {
            if (currentTime - continueStartTime > continueTime) start(scan_continue_mode);
        }
        return;
    }

    // sniffer
    if (isSniffing()) {
        // update packet list every 1s
        if (currentTime - snifferPacketTime > 1000) {
            snifferPacketTime = currentTime;
            list->add(packets);

            if (list->size() > SCAN_PACKET_LIST_SIZE) list->remove(0);
            deauths    = tmpDeauths;
            tmpDeauths = 0;
            packets    = 0;
        }

        // print status every 3s
        if (currentTime - snifferOutputTime > 3000) {
            char s[100];

            if (sniffTime > 0) {
                sprintf(s, str(SC_OUTPUT_A).c_str(), getPercentage(), packets, stations.count(), deauths);
            } else {
                sprintf(s, str(SC_OUTPUT_B).c_str(), packets, stations.count(), deauths);
            }
            prnt(String(s));
            snifferOutputTime = currentTime;
        }

        // channel hopping
        if (channelHop && (currentTime - snifferChannelTime > settings::getSnifferSettings().channel_time)) {
            snifferChannelTime = currentTime;

            if (scanMode == SCAN_MODE_STATIONS) nextChannel();  // go to next channel an AP is on
            else setChannel(wifi_channel + 1);                  // go to next channel
        }
    }

    // APs
    if ((scanMode == SCAN_MODE_APS) || (scanMode == SCAN_MODE_ALL)) {
        int16_t results = WiFi.scanComplete();

        if (results >= 0) {
            for (int16_t i = 0; i < results && i < 256; i++) {
                if (channelHop || (WiFi.channel(i) == wifi_channel)) accesspoints.add(i, false);
            }
            accesspoints.sort();
            accesspoints.printAll();

            if (scanMode == SCAN_MODE_ALL) {
                delay(30);
                start(SCAN_MODE_STATIONS);
            }
            else start(SCAN_MODE_OFF);
        }
    }

    // Stations
    else if ((sniffTime > 0) && (currentTime > snifferStartTime + sniffTime)) {
        wifi_promiscuous_enable(false);

        if (scanMode == SCAN_MODE_STATIONS) {
            stations.sort();
            stations.printAll();
        }
        start(SCAN_MODE_OFF);
    }
}

void Scan::setup() {
    save(true);
}

void Scan::stop() {
    scan_continue_mode = SCAN_MODE_OFF;
    start(SCAN_MODE_OFF);
}

void Scan::setChannel(uint8_t ch) {
    if (ch > 14) ch = 1;
    else if (ch < 1) ch = 14;

    wifi_promiscuous_enable(0);
    setWifiChannel(ch, true);
    wifi_promiscuous_enable(1);
}

void Scan::nextChannel() {
    if (accesspoints.count() > 1) {
        uint8_t ch = wifi_channel;

        do {
            ch++;

            if (ch > 14) ch = 1;
        } while (!apWithChannel(ch));
        setChannel(ch);
    }
}

bool Scan::apWithChannel(uint8_t ch) {
    for (int i = 0; i < accesspoints.count(); i++)
        if (accesspoints.getCh(i) == ch) return true;

    return false;
}

void Scan::save(bool force, String filePath) {
    String tmp = FILE_PATH;

    FILE_PATH = filePath;
    save(true);
    FILE_PATH = tmp;
}

void Scan::save(bool force) {
    if (!(accesspoints.changed || stations.changed) && !force) return;

    // Accesspoints
    String buf = String(OPEN_CURLY_BRACKET) + String(DOUBLEQUOTES) + str(SC_JSON_APS) + String(DOUBLEQUOTES) + String(
        DOUBLEPOINT) + String(OPEN_BRACKET); // {"aps":[

    if (!writeFile(FILE_PATH, buf)) {        // overwrite old file
        prnt(F_ERROR_SAVING);
        prntln(FILE_PATH);
        return;
    }

    buf = String(); // clear buffer
    uint32_t apCount = accesspoints.count();

    for (uint32_t i = 0; i < apCount; i++) {
        buf += String(OPEN_BRACKET) + String(DOUBLEQUOTES) + escape(accesspoints.getSSID(i)) + String(DOUBLEQUOTES) +
               String(COMMA);                                                                                    // ["ssid",
        buf += String(DOUBLEQUOTES) + escape(accesspoints.getNameStr(i)) + String(DOUBLEQUOTES) + String(COMMA); // "name",
        buf += String(accesspoints.getCh(i)) + String(COMMA);                                                    // 1,
        buf += String(accesspoints.getRSSI(i)) + String(COMMA);                                                  // -30,
        buf += String(DOUBLEQUOTES) + accesspoints.getEncStr(i) + String(DOUBLEQUOTES) + String(COMMA);          // "wpa2",
        buf += String(DOUBLEQUOTES) + accesspoints.getMacStr(i) + String(DOUBLEQUOTES) + String(COMMA);          // "00:11:22:00:11:22",
        buf += String(DOUBLEQUOTES) + accesspoints.getVendorStr(i) + String(DOUBLEQUOTES) + String(COMMA);       // "vendor",
        buf += b2s(accesspoints.getSelected(i)) + String(CLOSE_BRACKET);                                         // false]

        if (i < apCount - 1) buf += String(COMMA);                                                               // ,

        if (buf.length() >= 1024) {
            if (!appendFile(FILE_PATH, buf)) {
                prnt(F_ERROR_SAVING);
                prntln(FILE_PATH);
                return;
            }

            buf = String(); // clear buffer
        }
    }

    // Stations
    buf += String(CLOSE_BRACKET) + String(COMMA) + String(DOUBLEQUOTES) + str(SC_JSON_STATIONS) + String(DOUBLEQUOTES) +
           String(DOUBLEPOINT) + String(OPEN_BRACKET); // ],"stations":[;
    uint32_t stationCount = stations.count();

    for (uint32_t i = 0; i < stationCount; i++) {
        buf += String(OPEN_BRACKET) + String(DOUBLEQUOTES) + stations.getMacStr(i) + String(DOUBLEQUOTES) +
               String(COMMA);                                                                          // ["00:11:22:00:11:22",
        buf += String(stations.getCh(i)) + String(COMMA);                                              // 1,
        buf += String(DOUBLEQUOTES) + stations.getNameStr(i) + String(DOUBLEQUOTES) + String(COMMA);   // "name",
        buf += String(DOUBLEQUOTES) + stations.getVendorStr(i) + String(DOUBLEQUOTES) + String(COMMA); // "vendor",
        buf += String(*stations.getPkts(i)) + String(COMMA);                                           // 123,
        buf += String(stations.getAP(i)) + String(COMMA);                                              // 0,
        buf += String(DOUBLEQUOTES) + stations.getTimeStr(i) + String(DOUBLEQUOTES) + String(COMMA);   // "<1min",
        buf += b2s(stations.getSelected(i)) + String(CLOSE_BRACKET);                                   // false]

        if (i < stationCount - 1) buf += String(COMMA);                                                // ,

        if (buf.length() >= 1024) {
            if (!appendFile(FILE_PATH, buf)) {
                prnt(F_ERROR_SAVING);
                prntln(FILE_PATH);
                return;
            }

            buf = String(); // clear buffer
        }
    }

    buf += String(CLOSE_BRACKET) + String(CLOSE_CURLY_BRACKET); // ]}

    if (!appendFile(FILE_PATH, buf)) {
        prnt(F_ERROR_SAVING);
        prntln(FILE_PATH);
        return;
    }

    accesspoints.changed = false;
    stations.changed     = false;
    prnt(SC_SAVED_IN);
    prntln(FILE_PATH);
}

uint32_t Scan::countSelected() {
    return accesspoints.selected() + stations.selected() + names.selected();
}

uint32_t Scan::countAll() {
    return accesspoints.count() + stations.count() + names.count();
}

bool Scan::isScanning() {
    return scanMode != SCAN_MODE_OFF;
}

bool Scan::isSniffing() {
    return scanMode == SCAN_MODE_STATIONS || scanMode == SCAN_MODE_SNIFFER;
}

uint8_t Scan::getPercentage() {
    if (!isSniffing()) return 0;

    return (currentTime - snifferStartTime) / (sniffTime / 100);
}

void Scan::selectAll() {
    accesspoints.selectAll();
    stations.selectAll();
    names.selectAll();
}

void Scan::deselectAll() {
    accesspoints.deselectAll();
    stations.deselectAll();
    names.deselectAll();
}

void Scan::printAll() {
    accesspoints.printAll();
    stations.printAll();
    names.printAll();
    ssids.printAll();
}

void Scan::printSelected() {
    accesspoints.printSelected();
    stations.printSelected();
    names.printSelected();
}

uint32_t Scan::getPackets(int i) {
    if (list->size() < SCAN_PACKET_LIST_SIZE) {
        uint8_t translatedNum = SCAN_PACKET_LIST_SIZE - list->size();

        if (i >= translatedNum) return list->get(i - translatedNum);

        return 0;
    } else {
        return list->get(i);
    }
}

String Scan::getMode() {
    switch (scanMode) {
        case SCAN_MODE_OFF:
            return str(SC_MODE_OFF);

        case SCAN_MODE_APS:
            return str(SC_MODE_AP);

        case SCAN_MODE_STATIONS:
            return str(SC_MODE_ST);

        case SCAN_MODE_ALL:
            return str(SC_MODE_ALL);

        case SCAN_MODE_SNIFFER:
            return str(SC_MODE_SNIFFER);

        default:
            return String();
    }
}

double Scan::getScaleFactor(uint8_t height) {
    return (double)height / (double)getMaxPacket();
}

uint32_t Scan::getMaxPacket() {
    uint16_t max = 0;

    for (uint8_t i = 0; i < list->size(); i++) {
        if (list->get(i) > max) max = list->get(i);
    }
    return max;
}

uint32_t Scan::getPacketRate() {
    return list->get(list->size() - 1);
}