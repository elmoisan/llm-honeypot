"""Analyze a GeoJSON world file and report feature coordinate counts."""

import json
import sys
import urllib.request
import urllib.error

URL = (
    'https://raw.githubusercontent.com/datasets/geo-countries/'
    'master/data/countries.geojson'
)


def iter_coords(obj):
    """Yield coordinate pairs from nested GeoJSON geometry data."""
    if isinstance(obj, dict):
        for value in obj.values():
            yield from iter_coords(value)
    elif isinstance(obj, list):
        if len(obj) >= 2 and all(isinstance(x, (int, float)) for x in obj[:2]):
            yield tuple(obj[:2])
        else:
            for item in obj:
                yield from iter_coords(item)


def count_coords(geo):
    """Count coordinate pairs per feature in the GeoJSON object."""
    total = 0
    feat_counts = []

    if 'features' in geo:
        for feature in geo['features']:
            coords = 0
            for coordinate in iter_coords(feature.get('geometry', {})):
                if (
                    isinstance(coordinate, (list, tuple))
                    and len(coordinate) == 2
                    and isinstance(coordinate[0], (int, float))
                ):
                    coords += 1
            feat_counts.append(coords)
            total += coords

    return len(geo.get('features', [])), total, feat_counts


def main():
    """Fetch the GeoJSON file, count coordinates, and print a summary."""
    try:
        request = urllib.request.urlopen(URL, timeout=20)
        data = request.read()
        size = len(data)
        geo = json.loads(data.decode('utf-8'))
    except (urllib.error.URLError, ValueError, json.JSONDecodeError) as error:
        print('ERROR', error)
        sys.exit(1)

    fcount, coords_total, feat_counts = count_coords(geo)
    feat_max = max(feat_counts) if feat_counts else 0
    feat_min = min(feat_counts) if feat_counts else 0

    print('file_bytes', size)
    print('features', fcount)
    print('total_coords', coords_total)
    print('max_coords_per_feature', feat_max)
    print('min_coords_per_feature', feat_min)


if __name__ == '__main__':
    main()
