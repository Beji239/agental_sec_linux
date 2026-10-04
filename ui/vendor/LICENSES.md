# Third party files bundled with the dashboard

Everything in this folder used to be fetched from the internet every time you
opened the dashboard. It is here now so that opening your own security tool
does not tell three other companies you did.

Nothing in this folder is ours. Licences below, all of them permissive.

,,,,

## leaflet.js, leaflet.css, images/

Leaflet 1.9.4, the map library.

BSD 2-Clause. Copyright (c) 2010-2023 Volodymyr Agafonkin, (c) 2010-2011
CloudMade. https://leafletjs.com

The `images/` folder is Leaflet's own marker and layer sprites. We do not draw
markers, we draw circles and lines, so nothing on the page requests them
today. They are here because `leaflet.css` refers to them and a stylesheet
quietly asking for files that are not there is the kind of small mess that
wastes somebody's afternoon later.

,,,,

## world.geojson

Country outlines, drawn as the base map instead of downloading map tiles.

Built from `world-atlas@2.0.2` (countries-110m), ISC licence, copyright
2013-2019 Michael Bostock. https://github.com/topojson/world-atlas

The underlying data is Natural Earth, which is public domain.
https://www.naturalearthdata.com

We converted the TopoJSON to GeoJSON and rounded every coordinate to two
decimal places. That is roughly a kilometre of precision, which is far more
than a zoomed out world map needs, and it took the file from about 600 KB to
about 170 KB.

,,,,

## fonts/

Inter (weights 300, 400, 500, 600) and JetBrains Mono (400, 600), latin
subset only.

Both SIL Open Font License 1.1.

* Inter, copyright The Inter Project Authors. https://github.com/rsms/inter
* JetBrains Mono, copyright The JetBrains Mono Project Authors.
  https://github.com/JetBrains/JetBrainsMono

Taken from the `@fontsource/inter` and `@fontsource/jetbrains-mono` packages.
