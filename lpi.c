#include "flowcalc.h"
#include "lpi/libprotoident.h"

bool init()
{
	return (lpi_init_library() == 0);
}

void header()
{
	printf("%%%% lpi 0.1 - libprotoident\n");
	printf("@attribute lpi_category string\n");
	printf("@attribute lpi_proto string\n");
}

void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	if (is_new)
		lpi_init_data(data);

	lpi_update_data(pkt, data, up);
}

void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	lpi_module_t *lm;

	lm = lpi_guess_protocol(data);
	printf(",%s,%s", lpi_print_category(lm->category), lm->name);

	return;
}

struct module module = {
	.size = sizeof(lpi_data_t),
	.init = init,
	.header = header,
	.pkt = pkt,
	.flow = flow
};
