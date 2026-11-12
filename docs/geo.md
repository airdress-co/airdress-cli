# Geo

The geo plugin keeps your places, plots and tracks on your airdress and
serves them at `geo.<your airdress>` over the standard OGC APIs, so QGIS
and other GIS tools open them directly. `airdress geo` is the same from a
terminal, with your sign-in.

A collection is a `GeoCollection` resource. Make and change one with
`airdress apply -f`, remove it with `airdress delete`:

```yaml
apiVersion: airdress.co/v1alpha1
kind: GeoCollection
metadata: { name: allotments }
spec:
  title: Allotment plots
  storage: queryable          # queryable (default) | sealed | public
  geometry: { types: [Point, Polygon] }
```

## Collections and items

```sh
airdress geo collections                         # id, scope, storage, title
airdress geo collections show allotments         # one collection
airdress geo items list allotments --limit 50    # id, geometry, properties
airdress geo items list allotments --bbox 11.4,48.0,11.7,48.2 --filter "bed = 'north'"
airdress geo items get allotments <id> > plot.geojson   # the Feature; its ETag on stderr
airdress geo items put allotments -f plot.geojson       # a new item; prints its id
airdress geo items put allotments <id> -f plot.geojson --if-match '"<etag>"'
airdress geo items delete allotments <id>               # asks first; --yes for scripts
```

A collection's id is its name and a short tag of whose it is
(`allotments~3f9a2c1b0d4e`): two people's `trips` are two collections.
Every command takes the bare name when only one collection you may read
has it, and the full id otherwise.

Items go in and out as GeoJSON, one Feature at a time, in longitude and
latitude (CRS84). With `--if-match`, a write that would overwrite someone
else's change is refused; read the item again and retry. A long listing
prints the `--cursor` for its next page.

```sh
airdress geo usage       # what you hold, against your limits
```

## Sharing with someone on your airdress

```sh
airdress geo share grant allotments --to <principal id> --action ReadData
airdress geo share grant allotments --to <principal id> --action WriteData
airdress geo share list allotments
airdress geo share revoke allotments --to <principal id> --action WriteData   # keeps ReadData
airdress geo share revoke allotments --to <principal id>                      # all of it
```

`ReadData` reads; `WriteData` writes and shows nothing back on its own.
Your own collections are yours to share; a household collection is the
airdress owner's. The owner cannot read your collections unless you share
them.

Granting more to someone who already has a grant, or taking part of one
back, replaces their grant. If the replacement is refused they are left
with nothing on that collection, never with more, and the command says so.

The owner's sign-in finds the geo install by itself. Anyone else passes
`--install <id>`, as the owner's `airdress plugins list` shows it.

## Links

```sh
airdress geo share link create allotments --precision 1km --ttl 7d   # prints the link
airdress geo share link list allotments                              # your links, never the link itself
airdress geo share link revoke allotments <id>
```

A link opens one collection, read-only, for whoever holds it, until it
expires or you revoke it. Points are shown no finer than its precision:
`exact`, `100m`, `1km`, `approximate` (the default), `20km` or `100km`.
A collection that may hold lines or polygons is shared exactly or not at
all, and a sealed collection of your own cannot be linked. Revoking a link
also ends every narrower link made from it.

Links are off until the airdress owner turns sharing on for geo.
