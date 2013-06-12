#!/bin/bash
# Make corrections to libprotoident results

sed "$@" -r \
	-e '/^([^,]+,){7}995,(.*,|)SSL\/TLS(,|$)/{s;Encryption,SSL/TLS;Mail,POP3S;g }' \
	-e '/^([^,]+,){7}465,(.*,|)SSL\/TLS(,|$)/{s;Encryption,SSL/TLS;Mail,SMTPS;g }' \
	-e '/^([^,]+,){7}6969,(.*,|)HTTP_NonStandard(,|$)/{s;P2P,HTTP_NonStandard;P2P,BitTorrent;g }' \
	-e '/^([^,]+,){7}2710,(.*,|)HTTP_NonStandard(,|$)/{s;P2P,HTTP_NonStandard;P2P,BitTorrent;g }' \
	-e '/^([^,]+,){7}3310,(.*,|)HTTP_NonStandard(,|$)/{s;P2P,HTTP_NonStandard;P2P,BitTorrent;g }' \
	-e '/(tracker|torrent|desync.com|h33t.com).*,Web,HTTP_NonStandard/{s;Web,HTTP_NonStandard;P2P,BitTorrent;g }' \
