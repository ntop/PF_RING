# PF_RING documentation

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

