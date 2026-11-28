![pfring_logo]
# PF_RING™

### Introduction

PF_RING™ is a Linux kernel module and user-space framework that allows you to process packets at high-rates while providing you a consistent API for packet processing applications.

### Who needs PF_RING™?
Basically everyone who has to handle many packets per second. The term ‘many’ changes according to the hardware you use for traffic analysis. It can range from 80k pkt/sec on a 1,2GHz ARM to more than 20M pkt/sec **per core** on a low-end 2,5GHz Xeon. PF_RING™ not only enables you to capture packets faster, it also captures packets more efficiently preserving CPU cycles.

### Documentation

If you want to learn more about PF_RING™ please visit the [User's Guide](https://www.ntop.org/guides/pf_ring) and the [API Documentation](http://www.ntop.org/guides/pf_ring_api/files.html).

### Building the User's Guide

The PF_RING User's Guide is a [VitePress](https://vitepress.dev) project in `doc/` (Markdown pages, same
URLs as the old Sphinx guide: `/guides/pf_ring/<page>.html`). Requires Node 18+ and `make`.

```
cd doc
make dist                 # build the static site into doc/dist (runs npm install if needed)
make serve                # build, then serve it at http://localhost:4173/guides/pf_ring/   (PORT=8080 make serve)
npm run dev               # live reload while editing: http://localhost:5173/guides/pf_ring/
npm run api               # regenerate the API pages (doc/api/) from the Doxygen comments of the headers
```

The pages are the `.md` files of `doc/`, the sidebar is `doc/.vitepress/nav.json`.

### Details
For more information about PF_RING™ and other ntop technologies, please visit [http://ntop.org](http://www.ntop.org/products/packet-capture/pf_ring/)

## License
PF_RING™ kernel module and drivers are distributed under the GNU GPLv2 license, LGPLv2.1 for the user-space PF_RING library, and are available in source code format.

[pfring_logo]: http://www.ntop.org/images/2025/06/pf_ring-ft-icon.webp
