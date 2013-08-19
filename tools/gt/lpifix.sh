#!/bin/bash
# Make corrections to libprotoident results
# vim: tw=999

sed -r \
	-e '/^([^,]+,){7}(6969|2710|3310),/{s;P2P,HTTP_NonStandard;P2P,BitTorrent;g }' \
	-e '/^([^,]+,){7}(6969|6881|2710),/{s;No_Payload,No_Payload;P2P,BitTorrent;g }' \
	-e '/^([^,]+,){7}80,/{s;No_Payload,No_Payload;Web,HTTP;g }' \
	-e '/^([^,]+,){7}443,/{s;No_Payload,No_Payload;Web,HTTPS;g }' \
	-e '/^([^,]+,){7}5222,/{s;No_Payload,No_Payload;Conferencing,XMPP;g }' \
	-e '/^([^,]+,){7}110,/{s;No_Payload,No_Payload;Mail,POP3;g }' \
	-e '/^teamviewer.com/{s;No_Payload,No_Payload;Remote_Access,Teamviewer;g }' \
	-e '/,Teredo,/ { /^([^,]+,){5,7}3544,/! { s;Tunnelling,Teredo;Unknown,Unknown;g }}'

#	-e '/^([^,]+,){7}(25260|1433|1080|9000|9090|8090|27977|8123|8088|3246|2479|8188|8008|2301|3389|7212),.*,\?dns_name,/{s;No_Payload,No_Payload;Malware,Scan;g }' \
#	-e '/(desync.com|h33t.com|tracker.harry.lu|torrenty.org|trackerbc.com|tracker.ex.ua|tracker.publicbt.org|sumotracker.org)[^,]*,/{s;^(([^,]+,){39})([^,]+,){2}(.*);\1P2P,BitTorrent,\4;g}' \
