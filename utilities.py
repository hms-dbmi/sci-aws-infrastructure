def read_settings_file(filename):
    d = {}
    with open(filename) as f:
        for line in f:
            (key, val) = line.split("=")
            d[key] = val.strip()
    return d