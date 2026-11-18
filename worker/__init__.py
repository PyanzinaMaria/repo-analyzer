"""Producer worker: bridges the frontend queue contract to the analyzer.

Consumes ``data/queue/{scan_id}.json`` jobs, runs the analyzer library on
the submitted payload (cloning GitHub links itself), and writes
``data/reports/{scan_id}/`` artifacts the web frontend serves.
"""

__version__ = "0.1.0"
