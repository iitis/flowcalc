flowcalc
========

A toolkit for calculating IP flow statistics in ARFF format out of raw PCAP traffic trace files.
Thanks to the libtrace library, flowcalc can read numerous input file formats (see the [full
list](http://research.wand.net.nz/software/libtrace.php)).

flowcalc is based on [libflowcalc](https://github.com/iitis/libflowcalc). By default, it will load
all `*.so` files found in the current directory and register its per-packet and per-flow callback
functions using the `lfc_register()` function of libflowcalc.

The `*.so` files are modules, which are responsible for calculating some set of flow statistics.
Each module receives each packet as the trace file is read and can use the libtrace API to access
the low-level packet data required for calculations. Once a given IP flow finishes, another function
in the module is called so that it prints the flow data to the standard output.

flowcalc uses the ARFF output file format readable e.g. by the WEKA and RapidMiner data-mining
environments.

flowdump
========

Another interesting program is flowdump, which for example can be used to rewrite one big PCAP file
into many smaller ones, one for each layer 7 protocol. This can be used for training
machine-learning IP traffic classification systems.

Packets can be rewritten basing on the value of any column found in the flowcalc output file.

How to write a flowcalc module
------------------------------

See `counters.c` for an example of a simple module. Basically, your C file needs to define a global
`struct module` variable named `module` (see `flowcalc.h`). This structure has a few fields:

* `size`: amount of per-flow data you need for your algorithm (the `data` parameter)
* `init`: pointer to function which will emit an ARFF header
* `pkt`:  pointer to per-packet callback
* `flow`: pointer to per-flow callback

For `pkt` and `flow`, see `libflowcalc.h` in the [libflowcalc](https://github.com/iitis/libflowcalc)
project:

	/** A per-packet callback function
	 * @param pdata  plugin data
	 * @param lf     flow data
	 * @param data   plugin flow data
	 * @param ts     packet timestamp
	 * @param up     if true, this packet flows in the same direction as the
	 *               the first packet that created the flow
	 * @param is_new true for first packet in flow
	 * @param pkt    libtrace packet - access to packet data
	 */
	typedef void (*pkt_cb)(struct lfc *lfc, void *pdata,
		struct lfc_flow *lf, void *data,
		double ts, bool up, bool is_new, libtrace_packet_t *pkt);

	/** A callback to call when a flow is closed
	 * @param pdata  plugin data
	 * @param lf     basic flow information
	 * @param data   flow data
	 */
	typedef void (*flow_cb)(struct lfc *lfc, void *pdata,
		struct lfc_flow *lf, void *data);
